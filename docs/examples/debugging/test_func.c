// test_func.c - Test program for denet profiler
// This program creates a simple function call hierarchy with
// deliberate off-CPU events for profiling and stack trace testing.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

// Function prototypes
void level1_function(int iterations);
void level2_function(int value);
void level3_function(int value);
void cpu_work(int milliseconds);
void io_work(int milliseconds);

// Global variables to prevent compiler optimizations
volatile int global_counter = 0;

int main(int argc, char *argv[]) {
    int iterations = 10; // Default iterations
    
    // Parse command line arguments
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0) {
            iterations = 10;
        }
    }
    
    printf("Test program starting with %d iterations\n", iterations);
    printf("PID: %d\n", getpid());
    
    // Run the test workload
    level1_function(iterations);
    
    printf("Test completed. Final counter: %d\n", global_counter);
    return 0;
}

// Top level function that calls other functions
void level1_function(int iterations) {
    printf("Level 1 function entered, will run %d iterations\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        printf("Iteration %d/%d\n", i+1, iterations);
        
        // Do some CPU work
        cpu_work(50);
        
        // Call the next level function
        level2_function(i);
        
        // Sleep between iterations (off-CPU time)
        io_work(500);
    }
    
    printf("Level 1 function completed\n");
}

// Mid-level function
void level2_function(int value) {
    // Increment counter
    global_counter += value;
    
    // Do some CPU work
    cpu_work(100);
    
    // Call the next level function
    level3_function(value * 2);
    
    // Some off-CPU time in the middle of the stack
    io_work(200);
}

// Leaf function that will be at the bottom of the stack
void level3_function(int value) {
    // More CPU work
    cpu_work(200);
    
    // Modify global counter to prevent optimization
    global_counter += value * 3;
    
    // Some off-CPU time at the deepest level
    io_work(300);
}

// Function that does pure CPU work for a specified duration
void cpu_work(int milliseconds) {
    // Get current time
    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Busy-wait loop
    int local_counter = 0;
    while (1) {
        // Do some meaningless work
        for (int i = 0; i < 10000; i++) {
            local_counter += i;
        }
        
        // Check if we've reached the desired duration
        clock_gettime(CLOCK_MONOTONIC, &current);
        long elapsed_ms = (current.tv_sec - start.tv_sec) * 1000 + 
                          (current.tv_nsec - start.tv_nsec) / 1000000;
        
        if (elapsed_ms >= milliseconds) {
            break;
        }
    }
    
    // Update global counter to prevent optimization
    global_counter += local_counter % 100;
}

// Function that simulates I/O work by sleeping
void io_work(int milliseconds) {
    // Use usleep for off-CPU time
    usleep(milliseconds * 1000);
}