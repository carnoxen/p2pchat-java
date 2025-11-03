package main.protocol;

import java.util.HashMap;

public class Header extends HashMap<String, String> {
    @Override
    public String toString() {
        var entries = this.entrySet().stream()
        .map(x -> "%s:%s".formatted(x.getKey(), x.getValue()))
        .toList();
        
        return String.join("\n", entries);
    }
}
