# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/jereyes/esp/esp-idf/components/bootloader/subproject"
  "/home/jereyes/Cryptography-IPN/Mensajes-Sobres-RSA/build/bootloader"
  "/home/jereyes/Cryptography-IPN/Mensajes-Sobres-RSA/build/bootloader-prefix"
  "/home/jereyes/Cryptography-IPN/Mensajes-Sobres-RSA/build/bootloader-prefix/tmp"
  "/home/jereyes/Cryptography-IPN/Mensajes-Sobres-RSA/build/bootloader-prefix/src/bootloader-stamp"
  "/home/jereyes/Cryptography-IPN/Mensajes-Sobres-RSA/build/bootloader-prefix/src"
  "/home/jereyes/Cryptography-IPN/Mensajes-Sobres-RSA/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/jereyes/Cryptography-IPN/Mensajes-Sobres-RSA/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/jereyes/Cryptography-IPN/Mensajes-Sobres-RSA/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
