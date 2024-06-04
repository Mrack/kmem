#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdio>
#include <iostream>
#include <sys/stat.h>

#define DEV_FILENAME "/dev/kmem"

#define OP_CMD_READ 0x400011
#define OP_CMD_WRITE 0x400012
#define OP_CMD_LISTMAP 0x400013


struct MEMORY {
    pid_t pid;
    intptr_t addr;
    void *buffer;
    size_t size;
};

class Device {
public:
    Device() = default;

    ~Device() {
        close(fd);
    }

    bool init() {
        fd = open(DEV_FILENAME, O_RDONLY);
        if (fd == -1) {
            chmod(DEV_FILENAME, 0666);
            fd = open(DEV_FILENAME, O_RDONLY);
            chmod(DEV_FILENAME, 0600);
            if (fd == -1) return false;
        }
        return true;
    }


    int call(int cmd, void *arg) {
        auto res = ioctl(fd, cmd, arg);
        return res;
    }

private:
    int fd = -1;
};

char hello[100] = "Hello, World!";


std::string read_proc_kmem(pid_t pid) {
    std::stringstream ss;
    std::string filepath = "/proc/kmem/" + std::to_string(pid);

    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening " << filepath << std::endl;
        return "";
    }

    ss << file.rdbuf();
    file.close();

    return ss.str();
}

int main() {
    int res;
    MEMORY mem{};
    Device dev;
    if (dev.init()) {
        mem.pid = getpid();
        res = dev.call(OP_CMD_LISTMAP, &mem);
        std::cout << read_proc_kmem(mem.pid) << std::endl;
        printf("pid: %d\n", mem.pid);
        char read_buffer[100]{0};
        mem.buffer = read_buffer;
        mem.addr = (intptr_t) hello;
        mem.size = 100;
        res = dev.call(OP_CMD_READ, &mem);
        printf("OP_CMD_READ Result: %d\n", &res);
        printf("OP_CMD_READ Result: %s\n", mem.buffer);

        char write_buffer[100] = "修改了";
        mem.buffer = write_buffer;
        mem.addr = (intptr_t) hello;
        mem.size = 100;
        res = dev.call(OP_CMD_WRITE, &mem);
        printf("OP_CMD_WRITE Result: %d\n", &res);
        printf("OP_CMD_WRITE Result: %s\n", hello);
    }
    return 0;
}
