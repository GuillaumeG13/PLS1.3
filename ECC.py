def doubleAndAdd(r, P) :
    T = P
    rb = bin(r)[3:]
    n = len(rb)  # rb has already been truncated by 1
    for i in range(0, n):
        T = T * 2
        if rb[i] == '1':
            T = T + P
    return (T)

#TODO : pass to an object
