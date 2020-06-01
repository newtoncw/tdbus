#!/bin/bash
trusted=$1
messages=$2
repeats=$3
datatype=$4

if [ $trusted -eq 1 ]; then
	directory="trusted"
else
	directory="untrusted"
fi

if [ ! -d "measurments" ]; then
	mkdir "measurments"
fi

cd "measurments"

if [ ! -d "$directory" ]; then
	mkdir "$directory"
fi

cd "$directory"

file=$(date +%Y-%m-%d-%H-%M-%S)
file="$file.csv"

touch $file

cd ..
cd ..

write_file="measurments/$directory/$file"

for i in $(seq 1 $repeats)
do
	echo -ne "running $i of $repeats"\\r
	./test_client $trusted $messages $datatype >> $write_file
	wait
done
echo
