#include <stdio.h>
#include "adrs.h"

int main(void)
{
    ADRS adrs;
    initADRS(&adrs);

    printf("%d\n", adrs.adrs[0]);
    printf("%d\n", adrs.adrs[1]);
    printf("%d\n", adrs.adrs[2]);
    printf("%d\n", adrs.adrs[3]);
    printf("\n");

    setLayerAddress(&adrs, 1231231);
    printf("%d\n", adrs.adrs[0]);
    printf("%d\n", adrs.adrs[1]);
    printf("%d\n", adrs.adrs[2]);
    printf("%d\n", adrs.adrs[3]);
    return 0;
}
