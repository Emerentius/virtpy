use camino::{Utf8Path, Utf8PathBuf};
use eyre::eyre;

const INVALID_UTF8_PATH: &str = "path is not valid utf8";

pub(crate) use eyre::Result;

#[allow(unused)]
pub trait ToUtf8Path<'a> {
    fn to_utf8_path(self) -> &'a Utf8Path;
    fn try_to_utf8_path(self) -> eyre::Result<&'a Utf8Path>;
}

impl<'a> ToUtf8Path<'a> for &'a std::path::Path {
    fn to_utf8_path(self) -> &'a Utf8Path {
        self.try_to_utf8_path().expect("path should be utf8")
    }

    fn try_to_utf8_path(self) -> eyre::Result<&'a Utf8Path> {
        Utf8Path::from_path(self).ok_or_else(|| eyre!("{INVALID_UTF8_PATH}: {self:?}"))
    }
}

pub trait IntoUtf8Pathbuf {
    fn into_utf8_pathbuf(self) -> Utf8PathBuf;
    fn try_into_utf8_pathbuf(self) -> eyre::Result<Utf8PathBuf>;
}

impl IntoUtf8Pathbuf for std::path::PathBuf {
    fn try_into_utf8_pathbuf(self) -> eyre::Result<Utf8PathBuf> {
        Utf8PathBuf::from_path_buf(self).map_err(|path| eyre!("{INVALID_UTF8_PATH}: {path:?}"))
    }

    fn into_utf8_pathbuf(self) -> Utf8PathBuf {
        self.try_into_utf8_pathbuf().expect("path should be utf8")
    }
}

pub trait DirEntryExt {
    fn utf8_path(&self) -> Utf8PathBuf;
    fn try_utf8_path(&self) -> eyre::Result<Utf8PathBuf>;
    fn utf8_file_name(&self) -> String;
}

impl DirEntryExt for fs_err::DirEntry {
    fn utf8_path(&self) -> Utf8PathBuf {
        self.try_utf8_path().expect("path should be utf8")
    }

    fn try_utf8_path(&self) -> eyre::Result<Utf8PathBuf> {
        self.path().try_into_utf8_pathbuf()
    }

    fn utf8_file_name(&self) -> String {
        self.file_name().into_string().expect(INVALID_UTF8_PATH)
    }
}

impl DirEntryExt for std::fs::DirEntry {
    fn utf8_path(&self) -> Utf8PathBuf {
        self.try_utf8_path().expect("path should be utf8")
    }

    fn try_utf8_path(&self) -> eyre::Result<Utf8PathBuf> {
        self.path().try_into_utf8_pathbuf()
    }

    fn utf8_file_name(&self) -> String {
        self.file_name().into_string().expect(INVALID_UTF8_PATH)
    }
}

pub trait TempDirExt<'a> {
    fn utf8_path(self) -> &'a Utf8Path;
    fn try_utf8_path(self) -> eyre::Result<&'a Utf8Path>;
}

impl<'a> TempDirExt<'a> for &'a tempdir::TempDir {
    fn utf8_path(self) -> &'a Utf8Path {
        self.try_utf8_path().expect("path should be utf8")
    }

    fn try_utf8_path(self) -> eyre::Result<&'a Utf8Path> {
        self.path().try_to_utf8_path()
    }
}
