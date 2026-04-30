CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11 -Iclassic_encryption -Imodern_encryption -Ihash

SRCS = main.c \
       classic_encryption/caesar.c \
       classic_encryption/affine.c \
       classic_encryption/vigenere.c \
       classic_encryption/playfair.c \
       classic_encryption/hill.c \
       modern_encryption/rc4.c \
       modern_encryption/des.c \
       modern_encryption/aes.c \
       hash/md5.c \
       hash/sha256.c

TARGET = crypto

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)
