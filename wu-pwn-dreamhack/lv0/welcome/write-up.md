
# Description
![Description](./images/2025-07-28_07-14.png "Exploit")

## Source
```c
#include <stdio.h>

int main(void) {
    FILE *fp;
    char buf[0x80] = {};
    size_t flag_len = 0;

    printf("Welcome To DreamHack Wargame!\n");

    fp = fopen("/flag", "r");
    fseek(fp, 0, SEEK_END);
    flag_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fread(buf, 1, flag_len, fp);
    fclose(fp);

    printf("FLAG : ");
    fwrite(buf, 1, flag_len, stdout);
}
```

### Problem

Theo source hàm fwrite sẽ in ra flag luôn cho chúng ta.

#### Solve

Dùng netcat để remote server 

Welcome To DreamHack Wargame!
FLAG : DH{XXXXXXXXXXXXXXXXXXXXXXXXX}

