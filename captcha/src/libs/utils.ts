export async function retry<T>(
    fn: () => Promise<T>,
    options?: { attempts?: number; delay?: number }
): Promise<T> {
    const { attempts = 3, delay = 100 } = options || {};

    for (let i = 0; i < attempts; i++) {
        try {
            return await fn();
        } catch (error) {
            if (i < attempts - 1) {
                await new Promise(resolve => setTimeout(resolve, delay));
            } else {
                // rethrow the last error if all attempts fail
                throw error;
            }
        }
    }

    // fallback error
    throw new Error('this should never be reached');
}
