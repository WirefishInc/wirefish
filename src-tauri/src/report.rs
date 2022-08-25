pub mod report {

    use std::path::Path;
    use std::fs::{self, OpenOptions};
    use std::io::{self, Write};
    use std::ffi::OsStr;

    pub fn write_report(output_path: &str, data: &str) -> Result<(), io::Error> {
        let path = Path::new(output_path);
        let file_exists = path.is_file();
        let file_extension = path.extension();

        // Check file extension is .txt
        if file_extension.is_none() || file_extension.and_then(OsStr::to_str).unwrap() != "txt" {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Provide a .txt file"));
        }

        if !file_exists {
            // Create parent directories if they don't exist
            let parent_directory = path.parent().unwrap();
            if !parent_directory.is_dir() {
                fs::create_dir_all(parent_directory)?;
            }
        }

        // Open file in append mode, create it if it doesn't exist
        let mut file = OpenOptions::new()
            .append(true)
            .create(!file_exists)
            .open(path)?;

        // Append data to file
        file.write_all(data.as_bytes())
    }
}