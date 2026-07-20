use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

/// Applies independent work on all logical CPUs while returning results in the
/// exact same order as `items`.
///
/// The indexed result slots make the generated Pak independent of thread
/// scheduling. A scoped pool is created per large entry so no background
/// threads or global runtime are required by applications embedding repak.
pub(crate) fn ordered_map<T, U, F>(items: &[T], parallel: bool, operation: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(usize, &T) -> U + Sync,
{
    let workers = worker_count(items.len(), parallel);
    ordered_parallel_map_with_workers(items, workers, operation)
}

/// Applies independent work in parallel while delivering completed results to
/// the caller in deterministic item order. The progress callback always runs
/// on the calling thread, so applications may safely update a `FnMut` UI hook.
pub(crate) fn ordered_map_with_progress<T, U, F, P>(
    items: &[T],
    parallel: bool,
    operation: F,
    mut completed: P,
) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(usize, &T) -> U + Sync,
    P: FnMut(usize, &T, &U),
{
    let workers = worker_count(items.len(), parallel);
    if items.is_empty() {
        return Vec::new();
    }
    if workers == 1 {
        return items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let value = operation(index, item);
                completed(index, item, &value);
                value
            })
            .collect();
    }

    let next = AtomicUsize::new(0);
    let (sender, receiver) = std::sync::mpsc::channel::<(usize, U)>();
    let mut results: Vec<Option<U>> = (0..items.len()).map(|_| None).collect();
    let mut next_completed = 0_usize;

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let sender = sender.clone();
            let operation = &operation;
            let next = &next;
            scope.spawn(move || loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(index) else {
                    break;
                };
                if sender.send((index, operation(index, item))).is_err() {
                    break;
                }
            });
        }
        drop(sender);

        for _ in 0..items.len() {
            let (index, value) = receiver
                .recv()
                .expect("parallel worker ended before returning every result");
            results[index] = Some(value);
            while let Some(value) = results.get(next_completed).and_then(Option::as_ref) {
                completed(next_completed, &items[next_completed], value);
                next_completed += 1;
            }
        }
    });

    results
        .into_iter()
        .map(|value| value.expect("parallel worker did not fill its result slot"))
        .collect()
}

pub(crate) fn worker_count(item_count: usize, parallel: bool) -> usize {
    if !parallel {
        return 1;
    }
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(item_count.max(1))
}

fn ordered_parallel_map_with_workers<T, U, F>(
    items: &[T],
    worker_count: usize,
    operation: F,
) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(usize, &T) -> U + Sync,
{
    if items.is_empty() {
        return Vec::new();
    }

    let worker_count = worker_count.clamp(1, items.len());
    if worker_count == 1 {
        return items
            .iter()
            .enumerate()
            .map(|(index, item)| operation(index, item))
            .collect();
    }

    let next = AtomicUsize::new(0);
    let results: Vec<_> = (0..items.len()).map(|_| Mutex::new(None)).collect();

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(index) else {
                    break;
                };
                let value = operation(index, item);
                match results[index].lock() {
                    Ok(mut slot) => *slot = Some(value),
                    Err(_) => panic!("parallel result slot was poisoned"),
                }
            });
        }
    });

    results
        .into_iter()
        .map(|slot| match slot.into_inner() {
            Ok(Some(value)) => value,
            Ok(None) => unreachable!("parallel worker did not fill its result slot"),
            Err(_) => panic!("parallel result slot was poisoned"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::{ordered_map_with_progress, ordered_parallel_map_with_workers};

    #[test]
    fn preserves_input_order_while_using_multiple_workers() {
        let items: Vec<_> = (0..32).collect();
        let first_wave = Arc::new(Barrier::new(4));
        let output = ordered_parallel_map_with_workers(&items, 4, |index, value| {
            if index < 4 {
                first_wave.wait();
            }
            value * 3
        });

        assert_eq!(
            output,
            items.iter().map(|value| value * 3).collect::<Vec<_>>()
        );
    }

    #[test]
    fn handles_empty_and_single_item_inputs() {
        assert!(
            ordered_parallel_map_with_workers::<u8, u8, _>(&[], 8, |_, value| *value).is_empty()
        );
        assert_eq!(
            ordered_parallel_map_with_workers(&[7], 8, |_, value| value + 1),
            [8]
        );
    }

    #[test]
    fn progress_is_delivered_in_input_order_on_the_calling_thread() {
        let items: Vec<_> = (0..32_u32).collect();
        let caller = std::thread::current().id();
        let mut completed = Vec::new();
        let output = ordered_map_with_progress(
            &items,
            true,
            |index, value| {
                if index % 2 == 0 {
                    std::thread::yield_now();
                }
                value * 2
            },
            |index, _, value| {
                assert_eq!(std::thread::current().id(), caller);
                completed.push((index, *value));
            },
        );
        assert_eq!(
            completed,
            items
                .iter()
                .enumerate()
                .map(|(index, value)| (index, value * 2))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            output,
            items.iter().map(|value| value * 2).collect::<Vec<_>>()
        );
    }
}
