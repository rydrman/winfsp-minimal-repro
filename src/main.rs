use std::str::FromStr;

use anyhow::{Context, Result};
use libc::c_void;
use tracing::instrument;

use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

use windows::Win32::{
    Foundation::STATUS_NONCONTINUABLE_EXCEPTION,
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR,
    },
    Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY,
};
use winfsp::filesystem::DirBuffer;
use winfsp_sys::FILE_ACCESS_RIGHTS;

fn main() {
    // because this function exits right away it does not
    // properly handle destruction of data, so we put the actual
    // logic into a separate function/scope
    std::process::exit(main2())
}
fn main2() -> i32 {
    let mut cmd = CmdWinFsp;
    let result = cmd.run();
    if let Err(err) = result {
        tracing::error!("{err:?}");
        1
    } else {
        0
    }
}

#[derive(Debug)]
pub struct CmdWinFsp;

impl CmdWinFsp {
    pub fn run(&mut self) -> Result<i32> {
        let env_filter = tracing_subscriber::filter::EnvFilter::from_str("debug").unwrap();
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_target(true)
            .with_thread_ids(true);
        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(env_filter)
            .init();

        let init_token = winfsp::winfsp_init().context("Failed to initialize winfsp")?;
        let fsp = winfsp::service::FileSystemServiceBuilder::default()
            .with_start(|| match start_service() {
                Ok(svc) => Ok(svc),
                Err(err) => {
                    tracing::error!("{err:?}");
                    Err(STATUS_NONCONTINUABLE_EXCEPTION)
                }
            })
            .with_stop(|fs| {
                stop_service(fs);
                Ok(())
            })
            .build("test", init_token)
            .unwrap();
        fsp.start()
            .join()
            .unwrap()
            .context("Filesystem failed during runtime")
            .map(|()| 0)
    }
}

fn start_service() -> Result<FileSystem> {
    tracing::info!("starting service...");
    let mut params = winfsp::host::VolumeParams::new(winfsp::host::FileContextMode::Node);
    params.filesystem_name("test");
    let mut test = FileSystem {
        fs: winfsp::host::FileSystemHost::new(params, FileSystemContext::default()).unwrap(),
    };
    test.fs
        .mount("C:\\test")
        .context("Failed to mount test filesystem")?;
    test.fs.start().context("Failed to start filesystem")?;
    Ok(test)
}

fn stop_service(fs: Option<&mut FileSystem>) {
    if let Some(f) = fs {
        tracing::info!("Stopping winfsp service...");
        f.fs.stop();
    }
}

struct FileSystem {
    fs: winfsp::host::FileSystemHost<'static>,
}

#[derive(Default)]
struct FileSystemContext;

struct FileContext {
    ino: u64,
    dir_buffer: DirBuffer,
}

impl FileContext {
    fn new(ino: u64) -> Self {
        Self {
            ino,
            dir_buffer: DirBuffer::new(),
        }
    }
}
impl std::fmt::Debug for FileContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileContext")
            .field("ino", &self.ino)
            .finish_non_exhaustive()
    }
}

impl winfsp::filesystem::FileSystemContext for FileSystemContext {
    type FileContext = FileContext;

    #[instrument(skip_all)]
    fn get_security_by_name(
        &self,
        file_name: &winfsp::U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        resolve_reparse_points: impl FnOnce(
            &winfsp::U16CStr,
        ) -> Option<winfsp::filesystem::FileSecurity>,
    ) -> winfsp::Result<winfsp::filesystem::FileSecurity> {
        let path = std::path::PathBuf::from(file_name.to_os_string());
        tracing::info!(?path, security=%security_descriptor.is_some(), "start");

        if let Some(security) = resolve_reparse_points(file_name.as_ref()) {
            return Ok(security);
        }

        // a path with no filename component is assumed to be the root path '\\'
        // so anything else is currently NotFound
        if path.file_name().is_some() {
            tracing::info!(" > done [not found]");
            return Err(winfsp::FspError::IO(std::io::ErrorKind::NotFound));
        }

        let mut file_sec = winfsp::filesystem::FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: FILE_ATTRIBUTE_DIRECTORY.0,
        };

        // default security copied from winfsp memfs implementation
        let sddl = windows::core::w!("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)");
        let mut psecurity_descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let mut psecurity_descriptor_len: u32 = 0;
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                SDDL_REVISION_1,
                &mut psecurity_descriptor as *mut PSECURITY_DESCRIPTOR,
                Some(&mut psecurity_descriptor_len as *mut u32),
            )?
        };
        tracing::debug!(%psecurity_descriptor_len, "parsed descriptor");
        file_sec.sz_security_descriptor = psecurity_descriptor_len as u64;

        match security_descriptor {
            None => {}
            Some(descriptor) if descriptor.len() as u64 <= file_sec.sz_security_descriptor => {
                tracing::warn!(
                    "needed {}, got {}",
                    file_sec.sz_security_descriptor,
                    descriptor.len()
                );
            }
            Some(descriptor) => unsafe {
                // enough space must be available in the provided buffer for us to
                // mutate/access it
                std::ptr::copy(
                    psecurity_descriptor.0 as *const c_void,
                    descriptor.as_mut_ptr(),
                    file_sec.sz_security_descriptor as usize,
                )
            },
        }

        tracing::info!(" > done");
        Ok(file_sec)
    }

    #[instrument(skip_all)]
    fn open(
        &self,
        file_name: &winfsp::U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut winfsp::filesystem::OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = std::path::PathBuf::from(file_name.to_os_string());
        tracing::info!(?path, ?granted_access, ?create_options, "start");

        if path.file_name().is_none() {
            // a path with no filename component is assumed to be the root path '\\'
            let context = FileContext::new(0);
            let info = file_info.as_mut();
            info.file_attributes = FILE_ATTRIBUTE_DIRECTORY.0;
            info.index_number = context.ino;
            tracing::info!(" > open done");
            Ok(context)
        } else {
            tracing::info!(" > open done [not found]");
            Err(winfsp::FspError::IO(std::io::ErrorKind::NotFound))
        }
    }

    #[instrument(skip_all)]
    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&winfsp::U16CStr>,
        marker: winfsp::filesystem::DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let pattern = pattern.map(|p| p.to_os_string());
        tracing::info!(?context, ?marker, buffer=%buffer.len(), ?pattern, "start");
        let written = context.dir_buffer.read(marker, buffer);
        tracing::debug!(%written, " > done");
        Ok(written)
    }

    #[instrument(skip_all)]
    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut winfsp::filesystem::FileInfo,
    ) -> winfsp::Result<()> {
        tracing::info!(?context, "start");

        if context.ino == 0 {
            file_info.file_attributes = FILE_ATTRIBUTE_DIRECTORY.0;
            file_info.index_number = context.ino;
            tracing::info!(" > done");
            Ok(())
        } else {
            tracing::info!(" > done [not found]");
            Err(winfsp::FspError::IO(std::io::ErrorKind::NotFound))
        }
    }

    #[instrument(skip_all)]
    fn close(&self, context: Self::FileContext) {
        tracing::info!(?context, "close")
    }
}
