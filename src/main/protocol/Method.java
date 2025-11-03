package main.protocol;

public enum Method {
    UNKNOWN, RELAYOK,

    /* Request Methods */
    CONNECT, DISCONNECT, KEYXCHG, KEYXCHGRST, MSGSEND,

    /* Response Methods */
    ACCEPT, DENY, BYE, KEYXCHGOK, KEYXCHGFAIL, MSGSENDOK, MSGSENDFAIL, MSGRECV
}
