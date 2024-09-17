#!/usr/bin/env bash



set -e
set -u

function usage {
	echo "Usage:"
	echo "$0 {path to extracted file system of firmware}\
 {optional: name of the file to store results - defaults to firmwalker.txt}"
	echo "Example: ./$0 linksys/fmk/rootfs/"
	exit 1
}

function msg {
    echo "$1" | tee -a $FILE
}

function getArray {
    array=() # Create array
    while IFS= read -r line
    do
        array+=("$line")
    done < "$1"
}

# Check for arguments
if [[ $# -gt 2 || $# -lt 1 ]]; then
    usage
fi

# Set variables
FIRMDIR=$1
if [[ $# -eq 2 ]]; then
    FILE=$2
else
    FILE="firmwalker.txt"
fi
# Remove previous file if it exists, is a file and doesn't point somewhere
if [[ -e "$FILE" && ! -h "$FILE" && -f "$FILE" ]]; then
    rm -f $FILE
fi

# Perform searches
msg "***Firmware Directory***"
msg $FIRMDIR
msg "***Search for password files***"
getArray "data/passfiles"
passfiles=("${array[@]}")
for passfile in "${passfiles[@]}"
do
    # 查找文件并将结果存储在变量中
    found_files=$(find "$FIRMDIR" -iname "$passfile" | cut -c$((${#FIRMDIR} + 1))-)
    
    # 检查是否找到文件
    if [ -n "$found_files" ]; then
        msg "##################################### $passfile"
        echo "$found_files" | tee -a "$FILE"
        msg ""
    fi
done
msg "***Search for Unix-MD5 hashes***"
egrep -sro '\$1\$\w{8}\S{23}' $FIRMDIR | tee -a $FILE
msg ""
if [[ -d "$FIRMDIR/etc/ssl" ]]; then
    msg "***List etc/ssl directory***"
    ls -l $FIRMDIR/etc/ssl | tee -a $FILE
fi
msg ""
msg "***Search for SSL related files***"
getArray "data/sslfiles"
sslfiles=("${array[@]}")
for sslfile in ${sslfiles[@]}
do
    # 查找文件并将结果存储在变量中
    found_files=$(find "$FIRMDIR" -iname "$sslfile" | cut -c$((${#FIRMDIR} + 1))-)
    
    # 检查是否找到文件
    if [ -n "$found_files" ]; then
        msg "##################################### $sslfile"
        echo "$found_files" | tee -a "$FILE"
        
        # 收集找到的文件路径
        certfiles=( $(find "$FIRMDIR" -iname "$sslfile") )
        : "${certfiles:=empty}"
        
        # 执行 Shodan 搜索
        if [ "${sslfile##*.}" = "pem" ] || [ "${sslfile##*.}" = "crt" ]; then
            for certfile in "${certfiles[@]}"
            do
                serialno=$(openssl x509 -in "$certfile" -serial -noout) || echo "Incorrect File Content:Continuing"
                serialnoformat="ssl.cert.serial:${serialno##*=}"
                if type "shodan" &> /dev/null ; then
                    shocount=$(shodan count "$serialnoformat")
                    if (( shocount > 0 )); then
                        msg "################# Certificate serial # found in Shodan ####################"
                        echo "$certfile" | cut -c$((${#FIRMDIR} + 1))- | tee -a "$FILE"
                        echo "$serialno" | tee -a "$FILE"
                        echo "Number of devices found in Shodan = $shocount" | tee -a "$FILE"
                        cat "$certfile" | tee -a "$FILE"
                        msg "###########################################################################"
                    fi
                else 
                    echo "Shodan CLI not found."
                fi
            done
        fi
        msg ""
    fi
done

msg ""
msg "***Search for SSH related files***"
getArray "data/sshfiles"
sshfiles=("${array[@]}")
for sshfile in ${sshfiles[@]}
do
    # 查找文件并将结果存储在变量中
    found_files=$(find "$FIRMDIR" -iname "$sshfile" | cut -c$((${#FIRMDIR} + 1))-)
    
    # 检查是否找到文件
    if [ -n "$found_files" ]; then
        msg "##################################### $sshfile"
        echo "$found_files" | tee -a "$FILE"
        msg ""
    fi
done
msg ""
msg "***Search for files***"
getArray "data/files"
files=("${array[@]}")
for file in ${files[@]}
do
    # 查找文件并将结果存储在变量中
    found_files=$(find "$FIRMDIR" -iname "$file" | cut -c$((${#FIRMDIR} + 1))-)
    
    # 检查是否找到文件
    if [ -n "$found_files" ]; then
        msg "##################################### $file"
        echo "$found_files" | tee -a "$FILE"
        msg ""
    fi
done
msg ""
msg "***Search for database related files***"
getArray "data/dbfiles"
dbfiles=("${array[@]}")
for dbfile in ${dbfiles[@]}
do
    # 查找文件并将结果存储在变量中
    found_files=$(find "$FIRMDIR" -iname "$dbfile" | cut -c$((${#FIRMDIR} + 1))-)
    
    # 检查是否找到文件
    if [ -n "$found_files" ]; then
        msg "##################################### $dbfile"
        echo "$found_files" | tee -a "$FILE"
        msg ""
    fi
done
msg ""
msg "***Search for shell scripts***"
msg "##################################### shell scripts"
find $FIRMDIR -iname "*.sh" | cut -c${#FIRMDIR}- | tee -a $FILE
msg ""
msg "***Search for other .bin files***"
msg "##################################### bin files"
find $FIRMDIR -iname "*.bin" | cut -c${#FIRMDIR}- | tee -a $FILE




msg ""
msg "***Search for patterns in files***"
getArray "data/patterns"
patterns=("${array[@]}")
for pattern in "${patterns[@]}"
do
    msg "-------------------- $pattern --------------------"
    # grep -lsirnw $FIRMDIR -e "$pattern" | cut -c${#FIRMDIR}- | tee -a $FILE
    grep -sRIE "$pattern" "$FIRMDIR" | sed "s|$FIRMDIR||" | sort | uniq | tee -a "$FILE"
    msg ""
done
msg ""
msg "***Search for web servers***"
msg "##################################### search for web servers"
getArray "data/webservers"
webservers=("${array[@]}")
for webserver in ${webservers[@]}
do
    # 查找文件并将结果存储在变量中
    found_files=$(find "$FIRMDIR" -iname "$webserver" | cut -c$((${#FIRMDIR} + 1))-)
    
    # 检查是否找到文件
    if [ -n "$found_files" ]; then
        msg "##################################### $webserver"
        echo "$found_files" | tee -a "$FILE"
        msg ""
    fi
done
msg ""




msg "***Search for important binaries***"
msg "##################################### important binaries"
getArray "data/binaries"
binaries=("${array[@]}")
for binary in "${binaries[@]}"
do
    # 查找文件并将结果存储在变量中
    found_files=$(find "$FIRMDIR" -iname "$binary" | cut -c$((${#FIRMDIR} + 1))-)
    
    # 检查是否找到文件
    if [ -n "$found_files" ]; then
        msg "##################################### $binary"
        echo "$found_files" | tee -a "$FILE"
        msg ""
    fi
done

msg ""
msg "***Search for ip addresses***"
msg "##################################### ip addresses"
grep -sRIEho '\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' --exclude-dir='dev' $FIRMDIR | sort | uniq | tee -a $FILE

msg ""
msg "***Search for urls***"
msg "##################################### urls"
grep -sRIEoh '(http|https|ftp)://[^/"]+' --exclude-dir='dev' $FIRMDIR | sort | uniq | tee -a $FILE

msg ""
msg "***Search for emails***"
msg "##################################### emails"
grep -sRIEoh '([[:alnum:]_.-]+@[[:alnum:]_.-]+?\.[[:alpha:].]{2,6})' "$@" --exclude-dir='dev' $FIRMDIR | sort | uniq | tee -a $FILE

msg ""
msg "***.conf***"
msg "##################################### conf"
grep -sRIEo '.*\.conf' --exclude-dir='dev' "$FIRMDIR" | sed "s|$FIRMDIR||" | sort | uniq | tee -a "$FILE"

#Perform static code analysis 
#eslint -c eslintrc.json $FIRMDIR | tee -a $FILE


