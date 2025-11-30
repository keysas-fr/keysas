#[cfg(test)]
mod tests_in {
    use crate::is_corrupted;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn test_is_corrupted() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("file.txt");
        File::create(&file).unwrap();
        assert!(!is_corrupted(file));
        let file = dir.path().join("file.txt");
        let file_corrupted = dir.path().join("file.txt.ioerror");
        File::create(&file).unwrap();
        File::create(&file_corrupted).unwrap();
        assert!(is_corrupted(file));
    }
}
