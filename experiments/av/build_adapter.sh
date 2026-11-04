#!/bin/sh
set -eu

# source固定パッチ適用済みARM64 Linuxツリーを、ネットワークなしでビルドする。
test "$(uname -s)" = Linux
test "$(uname -m)" = aarch64
test "$#" = 2
filegate_source=$1
filegate_prefix=$2
test -d "$filegate_source/.cargo/vendor"
test -f "$filegate_source/libfreshclam/filegate_control.c"
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
echo FILEGATE_BUILD_PHASE=configure
cmake -S "$filegate_source" -B "$filegate_source/build-filegate" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$filegate_prefix" \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_C_COMPILER=/usr/bin/gcc \
  -DCMAKE_CXX_COMPILER=/usr/bin/g++ \
  '-DCMAKE_INSTALL_RPATH=$ORIGIN' \
  -DENABLE_APP=OFF \
  -DMAINTAINER_MODE=OFF \
  -DENABLE_EXPERIMENTAL=OFF \
  -DENABLE_LIBCLAMAV_ONLY=OFF \
  -DENABLE_SHARED_LIB=ON \
  -DENABLE_STATIC_LIB=OFF \
  -DENABLE_TESTS=ON \
  -DENABLE_EXAMPLES=OFF \
  -DENABLE_MILTER=OFF \
  -DENABLE_CLAMONACC=OFF \
  -DENABLE_SYSTEMD=OFF \
  -DENABLE_MAN_PAGES=OFF \
  -DENABLE_DOXYGEN=OFF \
  -DENABLE_EXTERNAL_MSPACK=ON \
  -DENABLE_JSON_SHARED=ON
echo FILEGATE_BUILD_PHASE=compile
cmake --build "$filegate_source/build-filegate" --parallel 2
echo FILEGATE_BUILD_PHASE=ctest
ctest --test-dir "$filegate_source/build-filegate" --output-on-failure
echo FILEGATE_BUILD_PHASE=install
cmake --install "$filegate_source/build-filegate" --component libraries
echo FILEGATE_BUILD_PHASE=complete
