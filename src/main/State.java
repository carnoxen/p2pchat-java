package main;

public sealed interface State {
    record START() implements State {}
    record WAITING() implements State {}
    record TALKING(String name) implements State {
        public String name() {
            return this.name;
        }
    }

    public default String name() {
        return this.getClass().getSimpleName();
    }
}
