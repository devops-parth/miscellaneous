#!/usr/bin/env bash

count=$(cat HR_file.txt | wc -l)
fCount=$(( $count + 1 ))

# Type1
sed -n "1,${fCount}p" HR_file.txt | cut -b 3

echo "*******************"

# Type2
for (( i=1; i<=$fCount; i++ ));
do
  # echo $i
  cat HR_file.txt | awk "NR==$i{print $1}" | cut -b 3
done

echo "*******************"

# Type 3
# > Suitable for each word basis and not line basis
for line in $(cat HR_file.txt)
do
    echo "$line" | cut -b 3
done
