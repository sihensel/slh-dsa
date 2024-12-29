#ifndef PARAMS_H
#define PARAMS_H

// Structure to hold parameters
typedef struct {
    int WOTS_HASH;
    int WOTS_PK;
    int TREE;
    int FORS_TREE;
    int FORS_ROOTS;
    int WOTS_PRF;
    int FORS_PRF;
    int lg_w;
    int w;
    int len2;
    int n;
    int h;
    int d;
    int h_;
    int a;
    int k;
    int m;
    int len1;
    int len;
} Parameters;

/*void setup_parameter_set(const char* name);*/
void setup_parameter_set(Parameters *prm, const char* name);

#endif
