#!/bin/sh
# Builds probe.dex against the framework jars from a built LineageOS 15.1 out/ tree.
#   LINEAGE_ROOT=/path/to/lineage ./build.sh
set -e
cd "$(dirname "$0")"
ROOT=${LINEAGE_ROOT:-$HOME/Desktop/android/lineage}
L=$ROOT/out/target/common/obj/JAVA_LIBRARIES
rm -rf classes && mkdir classes
javac -source 1.8 -target 1.8 -nowarn \
  -bootclasspath $L/core-oj_intermediates/classes.jar:$L/core-libart_intermediates/classes.jar \
  -cp $L/framework_intermediates/classes.jar -d classes src/com/bx/Probe.java
java -jar $ROOT/out/host/linux-x86/framework/dx.jar --dex --output=probe.dex classes
rm -rf classes
echo built probe.dex
