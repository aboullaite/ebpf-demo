#!/bin/sh
# Run the program
java -cp bcc.jar --enable-preview --source 21 --enable-native-access=ALL-UNNAMED $JAVA_OPTS $1 $@