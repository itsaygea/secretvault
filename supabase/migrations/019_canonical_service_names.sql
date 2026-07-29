-- SV-053: canonicalize service profile names to lowercase.
--
-- Profile names are matched against proxy scopes, which the authz layer
-- normalizes to lowercase. Storing mixed-case names made mixed-case profiles
-- impossible to authorize consistently and allowed case-variant duplicates
-- against a case-sensitive unique constraint. The application now stores the
-- canonical (lowercase) name at creation and canonicalizes the URL segment and
-- proxy lookup. This migration brings existing rows in line.
--
-- Lowercase every profile name. If two case-variants of the same name existed
-- (e.g. "GitHub" and "github") they would collide on the unique constraint; the
-- duplicate is resolved deterministically by keeping the most recently created
-- row and renaming the older one with a suffix so no data is lost silently.
-- Operators should review suffixed profiles and delete the redundant one.

-- Detect case collisions up front and rename the older row of each pair so the
-- bulk lowercase update cannot violate UNIQUE(user_id, name).
WITH ranked AS (
  SELECT id,
         user_id,
         LOWER(name) AS canonical,
         ROW_NUMBER() OVER (
           PARTITION BY user_id, LOWER(name)
           ORDER BY created_at DESC, id DESC
         ) AS rn
  FROM secretvault.service_profiles
)
UPDATE secretvault.service_profiles AS p
SET name = p.name || '_case_conflict_' || SUBSTRING(r.id::text, 1, 8)
FROM ranked r
WHERE r.id = p.id AND r.rn > 1;

-- Now lowercase the surviving names.
UPDATE secretvault.service_profiles SET name = LOWER(name) WHERE name <> LOWER(name);

-- Add a canonical (lowercased) unique index as defense in depth. The text is
-- already lowercase after the update, but this index guarantees no future
-- case-variant duplicate can exist even if a row is inserted out-of-band.
CREATE UNIQUE INDEX IF NOT EXISTS uq_service_profiles_user_canonical_name
  ON secretvault.service_profiles (user_id, lower(name));
