package com.sharker.ndkdemo;

/**
 * 1. 类的用途
 * 2. @author：liqingyi
 * 3. @date：2017/4/18 16:10
 */

public class Hello {
    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public native String stringFromJNIC();
}
