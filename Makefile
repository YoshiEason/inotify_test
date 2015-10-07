include /env.mak

SRC=inotify_test.cpp

inotify_test:$(SRC:.cpp=.o)
	$(CXX) -o $@ $(SRC:.cpp=.o) $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf inotify_test *.o
