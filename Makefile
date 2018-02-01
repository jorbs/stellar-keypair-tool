CC=g++
CXXFLAGS=`pkg-config --cflags libsodium` -std=c++11
LDFLAGS=`pkg-config --libs libsodium` -lpthread
OBJ=keypair.o lib/crc16.o
TARGET=keypair

$(TARGET): $(OBJ)
	$(CC) $(CXXFLAGS) -o $@ $(OBJ) $(LDFLAGS)
clean:
	rm $(OBJ) $(TARGET)
