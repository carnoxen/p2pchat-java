package main.protocol;

import java.util.LinkedList;

public class Body extends LinkedList<String> {
    @Override
    public String toString() {
        return String.join("\n", this);
    }
}
