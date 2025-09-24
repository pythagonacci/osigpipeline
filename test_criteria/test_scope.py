def test_scope():
    x = 1
    
    def f():
        x = 2
        y = x
        return y
    
    return f()
