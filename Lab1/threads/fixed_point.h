//17.14 fixed point calculation represent in B.6.
// x and y means fixed point and n means integer

#define f (1<<14)

// Convert n to fixed point:
#define n_to_fixed(n) (n)*(f)

//Convert x to integer (rounding toward zero)
#define x_to_integer_round_zero(x) (x) / (f)

//Convert x to integer (rounding to nearest)
#define x_to_integer_round_nearest(x) (x>=0)?((x)+(f)/2)/(f):((x)-(f)/2)/ (f)

//Add x and y
#define add_x_y(x, y) (x)+(y)

//Subtract y from x
#define sub_x_y(x, y) (x)-(y)

//Add x and n
#define add_x_n(x, n) (x)+(n)*(f)

//Subtract n from x
#define sub_x_n(x, n) (x)-(n)*(f)

//Multiply x by y
#define mul_x_y(x, y) ((int64_t)(x))*(y)/(f)

//Multiply x by n
#define mul_x_n(x, n) (x)*(n)

//Divide x by y
#define div_x_y(x, y) ((int64_t)(x))*(f)/(y)

//Divide x by n
#define div_x_n(x, n) (x)/(n)
