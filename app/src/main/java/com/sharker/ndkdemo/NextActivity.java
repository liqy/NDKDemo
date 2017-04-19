package com.sharker.ndkdemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

public class NextActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_next);
        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        Hello hello=new Hello();
        tv.setText(hello.stringFromJNI());
    }
}
