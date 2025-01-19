FileListUpdateWithHash(){
    # Comma-separated list of file/folder paths
    INPUT_PATHS="/home/thanuja/"

    # Initialize the FILELIST array
    FILELIST=()

    # Convert comma-separated paths into an array
    IFS=',' read -ra PATHS <<< "$INPUT_PATHS"
 
    # Iterate over each path

    for path in "${PATHS[@]}"; do
        if [ -f "$path" ]; then
            # If the path is a file, append the full path to FILELIST
            FILELIST+=("$path")
        elif [ -d "$path" ]; then
            # If the path is a directory, find all files in the directory recursively
            while IFS= read -r file; do
		        if [[ ! "$(basename "$file")" =~ ^\..* ]]; then
                    FILELIST+=("$file")
		        fi
            done < <(find "$path" -type f ! -path '*/.*')
        fi
    done

    # Iterate over the FILELIST to calculate hashes
    declare -A listOfFilesAndHash 
    for file in "${FILELIST[@]}"; do
        hashFilePair=$(md5sum "$file")
        read hash _ <<< "$hashFilePair"
        listOfFilesAndHash["$file"]=$hash
    done

    # Optional: Print out file hashes
    for file in "${!listOfFilesAndHash[@]}"; do
        echo "$file - ${listOfFilesAndHash[$file]}"
    done

    fileOfListOfHash="/var/logsign/log/filesToBeMonitoredAndHashes.log"
    # Check if the file exists, create it if it doesn't
    if [ ! -f "$fileOfListOfHash" ]; then
        # Ensure the directory path exists
        mkdir -p "$(dirname "$fileOfListOfHash")"

        # Create the file if it doesn't exist
        touch "$fileOfListOfHash"
    fi

    # Clear the contents of the file before appending
    cat /dev/null > "$fileOfListOfHash"
    for key in "${!listOfFilesAndHash[@]}"; do
        echo -e "File: $key, \tHash: ${listOfFilesAndHash[$key]}" >> "$fileOfListOfHash"
    done
}
FileListUpdateWithHash
