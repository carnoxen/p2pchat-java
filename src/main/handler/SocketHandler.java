package main.handler;

import java.nio.channels.CompletionHandler;

import main.SocketContext;

public interface SocketHandler<V> extends CompletionHandler<V, SocketContext> {}
