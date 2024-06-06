#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdio>
#include <iostream>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#define DEV_FILENAME "/dev/kmem"

#define OP_CMD_READ 0x400011 //读
#define OP_CMD_WRITE 0x400012 //写
#define OP_CMD_LISTMAP 0x400013 //映射map
#define OP_CMD_ROOT 0x400014 //root提权
#define OP_HIDE_MODULE 0x400015
#define OP_SHOW_MODULE 0x400016
#define OP_TT 0x400017

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

    bool init(int mode) {
        switch (mode) {
            case 1:
                fd = socket(AF_INET, SOCK_STREAM, 6);
                break;
            case 2:
                fd = open(DEV_FILENAME, O_RDONLY);
                break;
            default:
                fd = -1;
        }

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


std::string read_tasks() {
    std::stringstream ss;
    std::string filepath = "/proc/kmem/tasks";

    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening " << filepath << std::endl;
        return "";
    }
    ss << file.rdbuf();
    file.close();
    return ss.str();
}

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

enum {
    SOCK_IOCTOL = 1,
    DEV_IOCTOL,
};

int main() {
    int res;
    MEMORY mem{};
    Device dev;
    if (!dev.init(DEV_IOCTOL)) {
        printf("init failed");
        return 1;
    }

    char read_buffer[100]{0};
    mem.pid = getpid();

    // 获取所有进程
    printf("%s", read_tasks().c_str());

    // 隐藏当前模块
    res = dev.call(OP_HIDE_MODULE, &mem);
    printf("OP_HIDE_MODULE Result: %d\n", res);

    // 取消隐藏当前模块
    res = dev.call(OP_SHOW_MODULE, &mem);
    printf("OP_SHOW_MODULE Result: %d\n", res);

    // 获取进程maps
    res = dev.call(OP_CMD_LISTMAP, &mem);
    printf("%s", read_proc_kmem(mem.pid).c_str());
    printf("OP_CMD_LISTMAP Result: %d\n", res);

    // 读内存
    mem.buffer = read_buffer;
    mem.addr = (intptr_t) hello;
    mem.size = 100;
    res = dev.call(OP_CMD_READ, &mem);
    printf("OP_CMD_READ Result: %d\n", res);
    printf("OP_CMD_READ Result: %s\n", mem.buffer);

    // 写内存
    char write_buffer[100] = "修改了123456";
    mem.buffer = write_buffer;
    mem.addr = (intptr_t) hello;
    mem.size = 100;
    res = dev.call(OP_CMD_WRITE, &mem);
    printf("OP_CMD_WRITE Result: %d\n", res);
    printf("OP_CMD_WRITE Result: %s\n", hello);
    return 0;
}
