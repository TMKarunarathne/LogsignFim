##### My Hash ####
###########################################
# FILELIST=`ls /root/TMK/secFolder/`
FILELISTUpdate2(){
    # echo "Start of the FILELISTUpdate2"

    FILELIST=()
    # Comma-separated list of file/folder paths ## INPUT_PATHS="/root/TMK/secFolder/,/home/thanuja/file2.txt,/var/log/file3.log"

    INPUT_PATHS="/root/TMK/secFolder/"

    # Convert comma-separated paths into an array
    IFS=',' read -ra PATHS <<< "$INPUT_PATHS"
 
    # Iterate over each path
    
    for path in "${PATHS[@]}"; do
        if [ -f "$path" ]; then
            # If the path is a file, append the full path to FILELIST
            FILELIST+=("$path")
            # echo "${FILELIST[@]}"
        elif [ -d "$path" ]; then
            # If the path is a directory, find all files in the directory recursively
            while IFS= read -r file; do
		        if [[ ! "$(basename "$file")" =~ ^\..* ]]; then
                    FILELIST+=("$file")
                    # echo "$file"
                    # echo "${FILELIST[@]}"
		        fi
            done < <(find "$path" -type f ! -path '*/.*')
        fi
    done
    
    # for file in ${FILELIST[@]}; do
    #     echo "$file"
    # done

    # echo "end of the FILELISTUpdate2"
}


FileListUpdate(){
    # echo "Start of the FileListUpdate"
    FILELISTUpdate2

    for fileName in ${FILELIST[@]}; do
        # echo "$file"
        hashFilePair=$(md5sum $fileName)
        #echo "$hashFilePair"
        read hash file <<< "$hashFilePair"
        # echo "$file - - - -> $hash"
        fileForHash[$file]=$hash
        # echo "$fileName ---- $file ---- $hash"
    done
    # echo "end of the FileListUpdate"
}
###########################################
FileListCheck(){
    # echo "Start of the FileListCheck"
    shouldUpdate=false
    unset IFS
    # FILELIST=`ls $1`
    FILELISTUpdate2

    for key in "${!fileForHash[@]}"; do
        oldHash="${fileForHash[$key]}"

        if [[ -e $key ]]; then
            # echo "$key file exists."
            keyStat=true
        else
            # echo "$key file does not exist. It was removed/deleted"
            shouldUpdate=true
            deletedFiles[$key]=$oldHash
            newHash=$oldHash
            output_file="/var/logsign/log/deletedFiles.log"

            # Check if the file exists, create it if it doesn't
            if [ ! -f "$output_file" ]; then
                # Ensure the directory path exists
                mkdir -p "$(dirname "$output_file")"

                # Create the file if it doesn't exist
                touch "$output_file"
            fi

            # Loop through the array and write its contents to the file
            lastModifiedTime=$(date) 
            echo -e "File: $key, \tHash: $oldHash, \tNoticedTime: $lastModifiedTime" >> "$output_file"

            ## logger command ##
            eventAction="DELETED"
            miniLogCreator
            ################
            FileDir="$key"
            file=$(basename $FileDir)
            filesrch="/$file\""


            #### /var/log/audit/audit.log this can be changed
            logs=$(grep "$filesrch.*nametype=DELETE" $auditLogPath | tail -n 1)            
            IFS=$'\n'  # Set the Internal Field Separator to newline
            for log in $logs; do
                #  echo "$log"
                echo " "
                eventID=$(echo "$log" | grep -oE 'audit\([0-9.]+:([0-9]+)' | awk -F: '{print $2}')
                syscallLog=$(grep -E "type=SYSCALL.*:$eventID\)" $auditLogPath)
                procTitleLog=$(grep -E "type=PROCTITLE.*:$eventID\)" $auditLogPath)
                #echo "$syscallLog"

                hexCommand=$(echo "$procTitleLog" | grep -o 'proctitle=[^ ]*' | awk -F'=' '{print $2}')
                command=$(echo "$hexCommand" | xxd -r -p | tr -d '\0')

                epochTime=$(echo "$log" | grep -oE 'audit\([0-9]*\.[0-9]*' | awk -F"(" '{print $2}')
                lastModifiedTime=$(TZ="Asia/Kolkata" date -d "@$epochTime" "+%Y-%m-%d %H:%M:%S")
                success=$(echo "$syscallLog" | grep -o 'success=[^ ]*' | awk -F'=' '{print $2}')
                # command=$(echo "$syscallLog" | grep -o 'comm="[^"]*"' | sed 's/comm="//;s/"//')
                keyWord=$(echo "$syscallLog" | grep -o 'key="[^"]*"' | sed 's/key="//;s/"//')
                action=$(echo "$syscallLog" | grep -o 'SYSCALL=[^ ]*' | awk -F'=' '{print $2}')
                auid=$(echo "$syscallLog" | grep -o 'AUID="[^"]*"' | sed 's/AUID="//;s/"//')

                logMes="LastModifiedTime=$lastModifiedTime, OS=$distro, EVENTSOURCEIP=$EVENTSOURCE_IP, EventType="FS", Event_Action=$eventAction, FileDir=$dir, Hash=$newHash, Success=$success, Command=$command, Key=$keyWord, Action=$action, AUID=$auid"
                echo "$logMes"
                echo "$logMes" >> $fimLogPath
            done
            unset IFS
            unset "fileForHash[$key]"
        fi        
    done 
    # for file in ${FILELIST[@]}; do
    #     echo "$file"
    # done

    for file in ${FILELIST[@]}; do
        if [[ -v fileForHash["$file"] ]]; then
            # echo "/root/TMK/secFolder/$file exists in the array."
            keyStat=true
            # echo "FileListCheck in for loop and if yes $file "
        else
            # echo "/root/TMK/secFolder/$file does not exist in the array. It sould be added to the array"
            # echo "FileListCheck in for loop and if no $file "
            hashFilePair=$(md5sum $file)
            #echo "$hashFilePair"
            read newHash key <<< "$hashFilePair"
            fileForHash[$key]=$newHash
            oldHash=$newHash
            shouldUpdate=true

            ## logger command ##
            eventAction="CREATED"
            miniLogCreator
            detailedLogCreator

        fi
    done

    if [ "$shouldUpdate" = true ]; then
        updateCurrentFile
    fi
    # echo "end of the FileListCheck"
}
###########################################
appendToDeletedList(){
    # echo "start of the appendToDeletedList"
    output_file="/var/logsign/log/deletedFiles.log"
    # Loop through the array and write its contents to the file
    echo "File: $key, \tHash: ${deletedFiles[$key]}" >> "$output_file"
    # echo "end of the appendToDeletedList"
}
###########################################
updateCurrentFile(){
    # Loop through the array and write its contents to the file
    ### fileOfListOfHash="/var/logsign/log/filesToBeMonitoredAndHashes.log" ##Updated in the main function
    # echo "start of the updateCurrentFile"
    cat /dev/null > "$fileOfListOfHash"
    for key in "${!fileForHash[@]}"; do
        echo -e "File: $key, \tHash: ${fileForHash[$key]}" >> "$fileOfListOfHash"
    done
    # echo "end of the updateCurrentFile"
}

#### $eventAction sholud define before use this function
miniLogCreator(){
    #### $eventAction $key $newHash sholud define before use this function
    EVENTSOURCE_IP=`hostname -I | awk '{print $1}'`
    distro=`cat /etc/os-release | grep -oP 'PRETTY_NAME="\K[^"]+'`
    IP=`who am i |awk '{match($0,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); ip = substr($0,RSTART,RLENGTH); print ip'}`
    dir=$key
    lastModifiedTime=$(stat -c "%y" $key 2>/dev/null)

    logMes="LastModifiedTime=$lastModifiedTime, OS=$distro, EVENTSOURCEIP=$EVENTSOURCE_IP, EventType="FS", Event_Action=$eventAction, FileDir=$dir, NewHash=$newHash, OldHash=$oldHash"
    echo "$logMes"
    echo "$logMes" >> $fimLogPath
}

detailedLogCreator(){
    #### $eventAction sholud define before use this function
    lastModifiedTime=$(stat -c "%y" $key 2>/dev/null)
    time="$lastModifiedTime"
    stime=$(date -d "$time" "+%s")
    ms=$(echo $time | awk '{sub(/.*\./,""); print substr($1, 1, 3)}')
    mstime=$(echo "$stime.$ms")

    FileDir="$dir"
    file=$(basename $FileDir)
    filesrch="$file\""
    logs=$(grep "$mstime.*$filesrch.*nametype=CREATE" $auditLogPath)

    if [ -z "$logs" ]; then
        echo "The variable is empty."
        logs=$(grep "$filesrch.*nametype=CREATE" $auditLogPath | tail -n 1)
    fi


    IFS=$'\n'  # Set the Internal Field Separator to newline
    for log in $logs; do
        #  echo "$log"
        echo " "
        eventID=$(echo "$log" | grep -oE 'audit\([0-9.]+:([0-9]+)' | awk -F: '{print $2}')
        syscallLog=$(grep -E "type=SYSCALL.*:$eventID\)" $auditLogPath)
        procTitleLog=$(grep -E "type=PROCTITLE.*:$eventID\)" $auditLogPath)
        #echo "$syscallLog"

        hexCommand=$(echo "$procTitleLog" | grep -o 'proctitle=[^ ]*' | awk -F'=' '{print $2}')
        command=$(echo "$hexCommand" | xxd -r -p | tr -d '\0')

        success=$(echo "$syscallLog" | grep -o 'success=[^ ]*' | awk -F'=' '{print $2}')
        # echo "Success status is : $success"
        # command=$(echo "$syscallLog" | grep -o 'comm="[^"]*"' | sed 's/comm="//;s/"//')
        keyWord=$(echo "$syscallLog" | grep -o 'key="[^"]*"' | sed 's/key="//;s/"//')
        action=$(echo "$syscallLog" | grep -o 'SYSCALL=[^ ]*' | awk -F'=' '{print $2}')
        auid=$(echo "$syscallLog" | grep -o 'AUID="[^"]*"' | sed 's/AUID="//;s/"//')

        logMes="LastModifiedTime=$lastModifiedTime, OS=$distro, EVENTSOURCEIP=$EVENTSOURCE_IP, EventType="FS", Event_Action=$eventAction, FileDir=$dir, NewHash=$newHash, OldHash=$oldHash, Success=$success, Command=$command, Key=$keyWord, Action=$action, AUID=$auid"
        echo "$logMes"
        echo "$logMes" >> $fimLogPath
    done
    # echo "end of the for loop"
    unset IFS
}

copyFileMonitor(){

    while IFS= read -r line; do
            # Split the line into key and value
            lineNumOld=$(echo "$line")  
    done < "$input_fileNum"

    # unset IFS

    lineNumCurrent=$(wc -l $auditLogPath | awk '{print $1}') # current numbers of logs
    # echo "lineNumCurrent = $lineNumCurrent"
    ### if the log file is exceed the size then it create another file. then line numbers are coming from zero.
    if [[ "$lineNumOld" -gt "$lineNumCurrent" ]]; then
        lineNumOld="1"
    fi

    cpLogs=$(sed -n "${lineNumOld},${lineNumCurrent}p" $auditLogPath | grep --line-buffered 'comm="cp".*key="LogsignFIM"')
    eventAction="COPIED" 
    # echo "cpLogs :"
    # echo "$cpLogs"

    IFS=$'\n'
    for log in $cpLogs; do
        #  echo "$log"
        echo " "
        EVENTSOURCE_IP=`hostname -I | awk '{print $1}'`
        distro=`cat /etc/os-release | grep -oP 'PRETTY_NAME="\K[^"]+'`
        IP=`who am i |awk '{match($0,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); ip = substr($0,RSTART,RLENGTH); print ip'}`
        # dir=$key

        # echo "######################################################"

        eventID=$(echo "$log" | grep -oE 'audit\([0-9.]+:([0-9]+)' | awk -F: '{print $2}')
        # echo "eventD = $eventID"
        syscallLog=$(grep -E "type=SYSCALL.*:$eventID\)" $auditLogPath)
        procTitleLog=$(grep -E "type=PROCTITLE.*:$eventID\)" $auditLogPath)
        pathLog=$(grep -E "type=PATH.*:$eventID\)" $auditLogPath)
        # echo "syscallLog = $syscallLog"
        # echo "procTitleLog = $procTitleLog"

        hexCommand=$(echo "$procTitleLog" | grep -o 'proctitle=[^ ]*' | awk -F'=' '{print $2}')
        command=$(echo "$hexCommand" | xxd -r -p | tr -d '\0')

        epochTime=$(echo "$log" | grep -oE 'audit\([0-9]*\.[0-9]*' | awk -F"(" '{print $2}')
        lastModifiedTime=$(TZ="Asia/Kolkata" date -d "@$epochTime" "+%Y-%m-%d %H:%M:%S")
        success=$(echo "$syscallLog" | grep -o 'success=[^ ]*' | awk -F'=' '{print $2}')
        # command=$(echo "$syscallLog" | grep -o 'comm="[^"]*"' | sed 's/comm="//;s/"//')
        keyWord=$(echo "$syscallLog" | grep -o 'key="[^"]*"' | sed 's/key="//;s/"//')
        action=$(echo "$syscallLog" | grep -o 'SYSCALL=[^ ]*' | awk -F'=' '{print $2}')
        auid=$(echo "$syscallLog" | grep -o 'AUID="[^"]*"' | sed 's/AUID="//;s/"//')

        dir=$(echo "$pathLog" | grep -o 'name=[^ ]*' | awk -F'=' '{print $2}')

        logMes="LastModifiedTime=$lastModifiedTime, OS=$distro, EVENTSOURCEIP=$EVENTSOURCE_IP, EventType="FS", Event_Action=$eventAction, FileDir=$dir, NewHash=$newHash, OldHash=$oldHash, Success=$success, Command=$command, Key=$keyWord, Action=$action, AUID=$auid"
        echo "$logMes"
        echo "$logMes" >> /var/log/fim.log ### if uncomment this please uncomment the line after 4 lines
    done
    unset IFS

    echo "$lineNumCurrent" > "$input_fileNum"

}
############################################
########      MAIN   FUNCTION      #########
############################################
declare -A fileForHash
declare -A deletedFiles
# declare -a FILELIST

auditLogPath="/var/log/audit/audit.log"

input_fileNum="/var/logsign/log/lineNum.txt"
if [ ! -f "$input_fileNum" ]; then
    # Ensure the directory path exists
    mkdir -p "$(dirname "$input_fileNum")"

    # Create the file if it doesn't exist
    touch "$input_fileNum"
fi

fimLogPath="/var/logsign/log/fim.log"
# Check if the file exists, create it if it doesn't
if [ ! -f "$fimLogPath" ]; then
    # Ensure the directory path exists
    mkdir -p "$(dirname "$fimLogPath")"

    # Create the file if it doesn't exist
    touch "$fimLogPath"
fi

FILELISTUpdate2
# Loop through the FILELIST array and apply the auditctl policy
for filepath in "${FILELIST[@]}"; do
    if [ -e "$filepath" ]; then
        # Apply the audit rule
        auditctl -w "$filepath" -p rwxa -k LogsignFIM
        echo "Audit policy applied for $filepath"
    else
        echo "File not found: $filepath"
    fi
done

# Specify the file which has the existing detaails about files and their hash values. 
fileOfListOfHash="/var/logsign/log/filesToBeMonitoredAndHashes.log" # rename as fileOfListOfHash

# Check if the input file exists
if [ -f "$fileOfListOfHash" ]; then
    # Read the input file line by line
    while IFS= read -r line; do
        # Split the line into key and value
        key=$(echo "$line" | awk -F 'File: ' '{print $2}' | awk -F ',' '{print $1}')
        value=$(echo "$line" | awk -F 'Hash: ' '{print $2}')
        # echo "$key ---> $value"
        fileForHash[$key]=$value
    done < "$fileOfListOfHash"

    # Display the imported array
    for key in "${!fileForHash[@]}"; do
        echo "Key: $key, Value: ${fileForHash[$key]}"
    done
else
    echo "Input file '$fileOfListOfHash' not found."
    
    FileListUpdate 

    # Ensure the directory path exists
    mkdir -p "$(dirname "$fileOfListOfHash")"

    # Create the file if it doesn't exist
    touch "$fileOfListOfHash"

    updateCurrentFile
fi

i=0
while [ $i -lt 10 ]; do
    FileListCheck
    
    #### file modification, creation, deletion, renaming and removing monitoring ###
    for key in "${!fileForHash[@]}"; do
        shouldUpdate=false
        oldHash="${fileForHash[$key]}"
        read newHash p <<< $(md5sum $key)
       # echo "old hash is $oldHash    ---->    new hash is $newHash"
        #echo "olhHash: $oldHash, newHash: $newHash"

        if [ "$oldHash" != "$newHash" ]; then
            shouldUpdate=true
            # echo "The file $key was changed."
            fileForHash[$key]=$newHash

            ## logger command ##
            eventAction="MODIFIED"
            miniLogCreator
            detailedLogCreator

            if [ "$shouldUpdate" = true ]; then
                updateCurrentFile
            fi     
        fi
    done

    ### file coping monitoring ###
    copyFileMonitor

    sleep 60
done

