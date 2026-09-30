// A copy of `list` with the item at `index` moved by `offset` places.
export function move(list, index, offset) {
  const next = [...list]
  const [item] = next.splice(index, 1)
  next.splice(index + offset, 0, item)
  return next
}
