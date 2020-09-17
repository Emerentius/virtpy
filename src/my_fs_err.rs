
use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ErrorKind {
    Canonicalize,
}

/// Contains an IO error that has a file path attached.
///
/// This type is never returned directly, but is instead wrapped inside yet
/// another IO error.
#[derive(Debug)]
pub(crate) struct Error {
    kind: ErrorKind,
    source: std::io::Error,
    path: PathBuf,
}

impl Error {
    pub fn new<P: Into<PathBuf>>(source: io::Error, kind: ErrorKind, path: P) -> io::Error {
        io::Error::new(
            source.kind(),
            Self {
                kind,
                source,
                path: path.into(),
            },
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        let path = self.path.display();

        match self.kind {
            ErrorKind::Canonicalize => write!(formatter, "failed to canonicalize path `{}`", path),
        }
    }
}

impl StdError for Error {
    fn cause(&self) -> Option<&dyn StdError> {
        self.source()
    }

    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.source)
    }
}
pub(crate) trait FsErrPathExt {
    fn canonicalize_err(&self) -> std::io::Result<PathBuf>;
}

impl FsErrPathExt for Path {
    fn canonicalize_err(&self) -> std::io::Result<PathBuf> {
        self.canonicalize()
            .map_err(|err| Error::new(err, ErrorKind::Canonicalize, self.to_owned()))
    }
}
