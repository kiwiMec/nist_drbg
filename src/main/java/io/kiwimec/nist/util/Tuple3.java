package io.kiwimec.nist.util;

public class Tuple3<K, V, D> {

    public final K first;
    public final V second;
    public final D third;
  
    public Tuple3(K first, V second, D third){
        this.first = first;
        this.second = second;
        this.third = third;
    }
    
}