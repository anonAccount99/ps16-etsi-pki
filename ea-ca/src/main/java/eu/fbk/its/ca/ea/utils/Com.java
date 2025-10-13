package eu.fbk.its.ca.ea.utils;

import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;
import org.jboss.logging.Logger;

import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.function.Predicate;

public class Com {
    static public <T> T runWithRetry(String operationName, Callable<T> supplier, Predicate<T> successCondition, Logger logger) throws Exception {
        // Define a retry policy: handle any Exception, wait 5 seconds between attempts.
        RetryPolicy<T> retryPolicy = new RetryPolicy<T>()
                .handle(Exception.class)
                .withDelay(Duration.ofSeconds(5));

        // Execute the supplier using Failsafe and the defined retry policy.
        T result = Failsafe.with(retryPolicy).get(() -> {
            logger.info("Attempting to retrieve " + operationName + "...");
            // Call the operation.
            T value = supplier.call();
            // Check if the result meets the success condition.
            if (!successCondition.test(value)) {
                // Throw an exception to trigger a retry if the condition is not met.
                throw new IllegalStateException(operationName + " not retrieved.");
            }
            // Return the successful result.
            return value;
        });
        logger.info("Successfully retrieved " + operationName + ": " + result.toString());
        return result;
    }
}
