-- Small, deterministic e-commerce demo database for pg-mcp-guard.
-- Usage: psql "$DATABASE_URL" -f seed/ecommerce.sql   (or: pg-mcp-guard --demo)

DROP TABLE IF EXISTS order_items, orders, products, customers, admin_users;

CREATE TABLE customers (
  id            serial PRIMARY KEY,
  full_name     text NOT NULL,
  email         text NOT NULL UNIQUE,
  phone         text,
  city          text NOT NULL,
  password_hash text NOT NULL,
  created_at    timestamptz NOT NULL
);
COMMENT ON TABLE customers IS 'Registered shoppers. Contains PII.';
COMMENT ON COLUMN customers.email IS 'Login email (PII, masked by policy)';
COMMENT ON COLUMN customers.password_hash IS 'bcrypt hash; hidden by policy';

CREATE TABLE products (
  id          serial PRIMARY KEY,
  sku         text NOT NULL UNIQUE,
  name        text NOT NULL,
  category    text NOT NULL,
  price_cents integer NOT NULL CHECK (price_cents > 0)
);
COMMENT ON TABLE products IS 'Catalog of sellable items.';

CREATE TABLE orders (
  id          serial PRIMARY KEY,
  customer_id integer NOT NULL REFERENCES customers(id),
  status      text NOT NULL CHECK (status IN ('pending', 'paid', 'shipped', 'refunded')),
  created_at  timestamptz NOT NULL
);
COMMENT ON TABLE orders IS 'One row per checkout.';

CREATE TABLE order_items (
  order_id         integer NOT NULL REFERENCES orders(id),
  product_id       integer NOT NULL REFERENCES products(id),
  quantity         integer NOT NULL CHECK (quantity > 0),
  unit_price_cents integer NOT NULL,
  PRIMARY KEY (order_id, product_id)
);
COMMENT ON COLUMN order_items.unit_price_cents IS 'Price at time of purchase, in cents';

-- Not in the demo policy's allowlist: the agent cannot see or query it.
CREATE TABLE admin_users (
  id        serial PRIMARY KEY,
  username  text NOT NULL UNIQUE,
  api_token text NOT NULL
);

INSERT INTO admin_users (username, api_token)
SELECT 'admin' || g, 'tok_' || md5('admin' || g) FROM generate_series(1, 3) AS g;

INSERT INTO customers (full_name, email, phone, city, password_hash, created_at)
SELECT 'Customer ' || g,
       'customer' || g || '@example.com',
       '+1-555-' || lpad((1000 + g)::text, 4, '0'),
       (ARRAY['Austin', 'Berlin', 'Toronto', 'Lisbon', 'Singapore'])[1 + g % 5],
       '$2b$12$' || md5(g::text),
       timestamptz '2024-01-01' + g * interval '1 day'
FROM generate_series(1, 200) AS g;

INSERT INTO products (sku, name, category, price_cents)
SELECT 'SKU-' || lpad(g::text, 4, '0'),
       (ARRAY['Mug', 'Notebook', 'Backpack', 'Headphones', 'Desk Lamp'])[1 + g % 5] || ' ' || g,
       (ARRAY['kitchen', 'office', 'travel', 'audio', 'home'])[1 + g % 5],
       500 + (g * 137) % 9500
FROM generate_series(1, 50) AS g;

INSERT INTO orders (customer_id, status, created_at)
SELECT 1 + (g * 7) % 200,
       (ARRAY['pending', 'paid', 'shipped', 'refunded'])[1 + g % 4],
       timestamptz '2025-01-01' + g * interval '6 hours'
FROM generate_series(1, 1000) AS g;

INSERT INTO order_items (order_id, product_id, quantity, unit_price_cents)
SELECT o.id, p.id, 1 + (o.id + p.id) % 3, p.price_cents
FROM orders o
JOIN products p ON p.id IN (1 + o.id % 50, 1 + (o.id * 3) % 50, 1 + (o.id * 11) % 50)
ON CONFLICT DO NOTHING;

ANALYZE;
