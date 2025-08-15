idf_component_register(SRCS "envelope-msg.c"
                    INCLUDE_DIRS "."
                    REQUIRES mbedtls spiffs setup)

spiffs_create_partition_image(storage ../partition FLASH_IN_PROJECT)
