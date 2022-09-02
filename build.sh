#!/bin/sh
export JAVA_HOME=/usr/local/Cellar/openjdk@11/11.0.12
export PATH=/usr/local/Cellar/openjdk@11/11.0.12/bin:$PATH
./gradlew build -x test