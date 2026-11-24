// Six multi-tenant tasks. Each one: an existing schema with seed data, a plain-language access rule
// as a developer would ask an agent, and checks that run real queries as different users.
// A read check compares the visible ids with the expected set: extra ids are a leak, missing ids break the app.
// A write check expects the statement to go through ("allow") or to be blocked or hit zero rows ("deny").

export type User = { role: "anon" | "authenticated"; claims?: Record<string, unknown> };
export type Check =
  | { name: string; as: string; read: string; expect: string[] }
  | { name: string; as: string; write: string; expect: "allow" | "deny" };
export type Task = { id: string; title: string; prompt: string; setup: string; users: Record<string, User>; checks: Check[] };

const ALICE = "11111111-1111-1111-1111-111111111111";
const BOB = "22222222-2222-2222-2222-222222222222";
const CAROL = "33333333-3333-3333-3333-333333333333";
const ADMIN = "44444444-4444-4444-4444-444444444444";
const MALLORY = "55555555-5555-5555-5555-555555555555";
const GUEST = "66666666-6666-6666-6666-666666666666";

const signedIn = (sub: string, extra: Record<string, unknown> = {}): User => ({
  role: "authenticated",
  claims: { sub, role: "authenticated", aud: "authenticated", is_anonymous: false, app_metadata: {}, user_metadata: {}, ...extra },
});
const users = (...rows: [string, string?, string?, boolean?][]) =>
  "insert into auth.users (id, raw_app_meta_data, raw_user_meta_data, is_anonymous) values " +
  rows.map(([id, app = "{}", meta = "{}", anon = false]) => `('${id}', '${app}', '${meta}', ${anon})`).join(", ") + ";";

const base = {
  anon: { role: "anon" } as User,
  alice: signedIn(ALICE),
  bob: signedIn(BOB),
  carol: signedIn(CAROL),
};

export const TASKS: Task[] = [
  {
    id: "notes",
    title: "Private notes",
    prompt: "Table public.notes holds private notes. Signed-in users may read, create, edit and delete only their own notes. " +
      "Signed-out visitors must not read or change anything.",
    setup: `
      ${users([ALICE], [BOB])}
      create table public.notes (id int primary key, user_id uuid not null references auth.users (id), body text not null);
      insert into public.notes values (1, '${ALICE}', 'a1'), (2, '${ALICE}', 'a2'), (3, '${BOB}', 'b1');`,
    users: base,
    checks: [
      { name: "alice reads her notes", as: "alice", read: "select id from public.notes", expect: ["1", "2"] },
      { name: "bob reads his notes", as: "bob", read: "select id from public.notes", expect: ["3"] },
      { name: "visitor reads nothing", as: "anon", read: "select id from public.notes", expect: [] },
      { name: "alice creates a note", as: "alice", write: `insert into public.notes values (10, '${ALICE}', 'new')`, expect: "allow" },
      { name: "alice creates a note in bob's name", as: "alice", write: `insert into public.notes values (11, '${BOB}', 'x')`, expect: "deny" },
      { name: "alice edits her note", as: "alice", write: "update public.notes set body = 'edited' where id = 1", expect: "allow" },
      { name: "alice hands her note to bob", as: "alice", write: `update public.notes set user_id = '${BOB}' where id = 1`, expect: "deny" },
      { name: "alice edits bob's note", as: "alice", write: "update public.notes set body = 'x' where id = 3", expect: "deny" },
      { name: "alice deletes her note", as: "alice", write: "delete from public.notes where id = 2", expect: "allow" },
      { name: "alice deletes bob's note", as: "alice", write: "delete from public.notes where id = 3", expect: "deny" },
      { name: "visitor creates a note", as: "anon", write: `insert into public.notes values (12, '${ALICE}', 'x')`, expect: "deny" },
      { name: "visitor deletes notes", as: "anon", write: "delete from public.notes", expect: "deny" },
    ],
  },
  {
    id: "teams",
    title: "Team projects with admins",
    prompt: "Users belong to teams via public.team_members (role 'admin' or 'member'). Members can read their own team's projects " +
      "and see who is in their team. Only team admins can create, rename or delete their team's projects and add or remove " +
      "members of their team. Nobody can see or change another team's data.",
    setup: `
      ${users([ALICE], [BOB], [CAROL])}
      create table public.teams (id int primary key, name text not null);
      create table public.team_members (
        team_id int not null references public.teams (id),
        user_id uuid not null references auth.users (id),
        role text not null check (role in ('admin', 'member')),
        primary key (team_id, user_id));
      create table public.projects (id int primary key, team_id int not null references public.teams (id), name text not null);
      insert into public.teams values (1, 'Team A'), (2, 'Team B');
      insert into public.team_members values (1, '${ALICE}', 'admin'), (1, '${BOB}', 'member'), (2, '${CAROL}', 'admin');
      insert into public.projects values (1, 1, 'a-web'), (2, 1, 'a-app'), (3, 2, 'b-web');`,
    users: base,
    checks: [
      { name: "member bob reads team A projects", as: "bob", read: "select id from public.projects", expect: ["1", "2"] },
      { name: "carol reads team B projects", as: "carol", read: "select id from public.projects", expect: ["3"] },
      { name: "bob sees his team's members", as: "bob", read: "select team_id || ':' || left(user_id::text, 1) as id from public.team_members", expect: ["1:1", "1:2"] },
      { name: "visitor reads nothing", as: "anon", read: "select id from public.projects", expect: [] },
      { name: "admin alice creates a project", as: "alice", write: "insert into public.projects values (10, 1, 'new')", expect: "allow" },
      { name: "admin alice renames a project", as: "alice", write: "update public.projects set name = 'renamed' where id = 1", expect: "allow" },
      { name: "admin alice adds carol to team A", as: "alice", write: `insert into public.team_members values (1, '${CAROL}', 'member')`, expect: "allow" },
      { name: "member bob creates a project", as: "bob", write: "insert into public.projects values (11, 1, 'x')", expect: "deny" },
      { name: "member bob renames a project", as: "bob", write: "update public.projects set name = 'x' where id = 1", expect: "deny" },
      { name: "admin alice creates a project in team B", as: "alice", write: "insert into public.projects values (12, 2, 'x')", expect: "deny" },
      { name: "admin alice moves a project to team B", as: "alice", write: "update public.projects set team_id = 2 where id = 1", expect: "deny" },
      { name: "member bob makes himself admin", as: "bob", write: `update public.team_members set role = 'admin' where team_id = 1 and user_id = '${BOB}'`, expect: "deny" },
      { name: "bob joins team B", as: "bob", write: `insert into public.team_members values (2, '${BOB}', 'admin')`, expect: "deny" },
    ],
  },
  {
    id: "tickets",
    title: "Support tickets with an admin flag",
    prompt: "Support tickets live in public.tickets. Users can read and create their own tickets. Support staff are admins: " +
      "our backend sets role = 'admin' in the user's Supabase Auth metadata, and admins can read and update every ticket.",
    setup: `
      ${users([ALICE], [MALLORY, "{}", '{"role": "admin"}'], [ADMIN, '{"role": "admin"}'])}
      create table public.tickets (id int primary key, user_id uuid not null references auth.users (id), subject text not null);
      insert into public.tickets values (1, '${ALICE}', 'login broken'), (2, '${MALLORY}', 'question');`,
    users: {
      anon: base.anon,
      alice: base.alice,
      // Mallory set user_metadata.role herself via supabase.auth.updateUser(); only app_metadata is set by the backend.
      mallory: signedIn(MALLORY, { user_metadata: { role: "admin" } }),
      admin: signedIn(ADMIN, { app_metadata: { role: "admin" } }),
    },
    checks: [
      { name: "alice reads her ticket", as: "alice", read: "select id from public.tickets", expect: ["1"] },
      { name: "mallory with self-set metadata reads only hers", as: "mallory", read: "select id from public.tickets", expect: ["2"] },
      { name: "admin reads every ticket", as: "admin", read: "select id from public.tickets", expect: ["1", "2"] },
      { name: "visitor reads nothing", as: "anon", read: "select id from public.tickets", expect: [] },
      { name: "alice opens a ticket", as: "alice", write: `insert into public.tickets values (10, '${ALICE}', 'new')`, expect: "allow" },
      { name: "alice opens a ticket as mallory", as: "alice", write: `insert into public.tickets values (11, '${MALLORY}', 'x')`, expect: "deny" },
      { name: "admin updates a ticket", as: "admin", write: "update public.tickets set subject = 'triaged' where id = 1", expect: "allow" },
      { name: "mallory updates alice's ticket", as: "mallory", write: "update public.tickets set subject = 'x' where id = 1", expect: "deny" },
    ],
  },
  {
    id: "posts",
    title: "Blog with drafts",
    prompt: "Blog posts live in public.posts. Anyone, signed in or not, can read published posts. Authors can also read their own drafts. " +
      "Signed-in users can write posts only as themselves and edit or delete only their own posts. Signed-out visitors cannot write.",
    setup: `
      ${users([ALICE], [BOB])}
      create table public.posts (id int primary key, author_id uuid not null references auth.users (id), title text not null, published boolean not null default false);
      insert into public.posts values (1, '${ALICE}', 'a live', true), (2, '${ALICE}', 'a draft', false), (3, '${BOB}', 'b live', true), (4, '${BOB}', 'b draft', false);`,
    users: base,
    checks: [
      { name: "visitor reads published posts", as: "anon", read: "select id from public.posts", expect: ["1", "3"] },
      { name: "alice reads published posts and her draft", as: "alice", read: "select id from public.posts", expect: ["1", "2", "3"] },
      { name: "bob reads published posts and his draft", as: "bob", read: "select id from public.posts", expect: ["1", "3", "4"] },
      { name: "alice publishes her draft", as: "alice", write: "update public.posts set published = true where id = 2", expect: "allow" },
      { name: "alice writes a post", as: "alice", write: `insert into public.posts values (10, '${ALICE}', 'new', false)`, expect: "allow" },
      { name: "alice edits bob's post", as: "alice", write: "update public.posts set title = 'x' where id = 3", expect: "deny" },
      { name: "alice writes as bob", as: "alice", write: `insert into public.posts values (11, '${BOB}', 'x', true)`, expect: "deny" },
      { name: "alice hands her post to bob", as: "alice", write: `update public.posts set author_id = '${BOB}' where id = 1`, expect: "deny" },
      { name: "alice deletes bob's post", as: "alice", write: "delete from public.posts where id = 3", expect: "deny" },
      { name: "visitor writes a post", as: "anon", write: `insert into public.posts values (12, '${ALICE}', 'x', true)`, expect: "deny" },
      { name: "visitor edits a post", as: "anon", write: "update public.posts set title = 'x' where id = 1", expect: "deny" },
    ],
  },
  {
    id: "shares",
    title: "Documents shared between users",
    prompt: "Documents in public.documents belong to their owner. Owners can do everything with their documents and decide who they " +
      "are shared with via public.document_shares. A user a document is shared with can read it; if can_edit is true, they can " +
      "also change title and content, but not the owner, and they cannot delete the document or change the sharing.",
    setup: `
      ${users([ALICE], [BOB], [CAROL])}
      create table public.documents (id int primary key, owner_id uuid not null references auth.users (id), title text not null, content text not null default '');
      create table public.document_shares (
        document_id int not null references public.documents (id) on delete cascade,
        user_id uuid not null references auth.users (id),
        can_edit boolean not null default false,
        primary key (document_id, user_id));
      insert into public.documents values (1, '${ALICE}', 'plan', ''), (2, '${ALICE}', 'budget', ''), (3, '${BOB}', 'notes', '');
      insert into public.document_shares values (1, '${BOB}', false), (2, '${CAROL}', true);`,
    users: base,
    checks: [
      { name: "alice reads her documents", as: "alice", read: "select id from public.documents", expect: ["1", "2"] },
      { name: "bob reads his and the one shared with him", as: "bob", read: "select id from public.documents", expect: ["1", "3"] },
      { name: "carol reads the one shared with her", as: "carol", read: "select id from public.documents", expect: ["2"] },
      { name: "visitor reads nothing", as: "anon", read: "select id from public.documents", expect: [] },
      { name: "editor carol changes content", as: "carol", write: "update public.documents set content = 'edited' where id = 2", expect: "allow" },
      { name: "owner alice shares with carol", as: "alice", write: `insert into public.document_shares values (1, '${CAROL}', false)`, expect: "allow" },
      { name: "reader bob changes content", as: "bob", write: "update public.documents set content = 'x' where id = 1", expect: "deny" },
      { name: "editor carol takes ownership", as: "carol", write: `update public.documents set owner_id = '${CAROL}' where id = 2`, expect: "deny" },
      { name: "editor carol deletes the document", as: "carol", write: "delete from public.documents where id = 2", expect: "deny" },
      { name: "reader bob gives himself edit rights", as: "bob", write: `update public.document_shares set can_edit = true where document_id = 1 and user_id = '${BOB}'`, expect: "deny" },
      { name: "bob shares alice's budget with himself", as: "bob", write: `insert into public.document_shares values (2, '${BOB}', true)`, expect: "deny" },
    ],
  },
  {
    id: "guests",
    title: "Shop with anonymous sign-ins",
    prompt: "The shop uses Supabase anonymous sign-ins. Anyone, even signed-out visitors, can browse public.products. Signed-in users, " +
      "including anonymous ones, keep their own cart in public.cart_items. Only permanent (non-anonymous) users can place orders " +
      "in public.orders and read their own orders.",
    setup: `
      ${users([ALICE], [GUEST, "{}", "{}", true])}
      create table public.products (id int primary key, name text not null);
      create table public.cart_items (id int primary key, user_id uuid not null references auth.users (id), product_id int not null references public.products (id));
      create table public.orders (id int primary key, user_id uuid not null references auth.users (id), total numeric not null);
      insert into public.products values (1, 'mug'), (2, 'shirt');
      insert into public.cart_items values (1, '${ALICE}', 1), (2, '${GUEST}', 2);
      insert into public.orders values (1, '${ALICE}', 12);`,
    users: {
      anon: base.anon,
      alice: base.alice,
      guest: { role: "authenticated", claims: { sub: GUEST, role: "authenticated", aud: "authenticated", is_anonymous: true, app_metadata: {}, user_metadata: {} } },
    },
    checks: [
      { name: "visitor browses products", as: "anon", read: "select id from public.products", expect: ["1", "2"] },
      { name: "guest reads own cart", as: "guest", read: "select id from public.cart_items", expect: ["2"] },
      { name: "alice reads own cart", as: "alice", read: "select id from public.cart_items", expect: ["1"] },
      { name: "alice reads own orders", as: "alice", read: "select id from public.orders", expect: ["1"] },
      { name: "guest reads no orders", as: "guest", read: "select id from public.orders", expect: [] },
      { name: "guest adds to cart", as: "guest", write: `insert into public.cart_items values (10, '${GUEST}', 1)`, expect: "allow" },
      { name: "alice places an order", as: "alice", write: `insert into public.orders values (10, '${ALICE}', 20)`, expect: "allow" },
      { name: "guest places an order", as: "guest", write: `insert into public.orders values (11, '${GUEST}', 20)`, expect: "deny" },
      { name: "guest fills alice's cart", as: "guest", write: `insert into public.cart_items values (11, '${ALICE}', 2)`, expect: "deny" },
      { name: "visitor adds a product", as: "anon", write: "insert into public.products values (10, 'x')", expect: "deny" },
      { name: "alice renames a product", as: "alice", write: "update public.products set name = 'x' where id = 1", expect: "deny" },
    ],
  },
];
