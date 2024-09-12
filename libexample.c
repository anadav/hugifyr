// libexample.c

// Read-only data section (constant string)
const char *ro_data = "This is read-only data from the library";

// Mutable data section (initialized global variable)
int data = 42;

// A function that uses both data and text sections
const char* get_ro_data() {
    return ro_data;
}

int get_data() {
    return data;
}

void set_data(int value) {
    data = value;
}

