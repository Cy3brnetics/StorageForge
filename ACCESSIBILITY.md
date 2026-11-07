# Accessibility

StorageForge's web interface should work for people who use a keyboard, a screen reader, magnification, or reduced motion. This page says
what has been done, what is known not to work well, and how to report a barrier.

## What it does

- **Keyboard.** Every view, panel and dialog can be reached and used without a mouse. The side rail is a tab list (arrows, Home, End), the
  map's nodes are buttons in reading order, the topology canvas zooms and fits from the keyboard, and **Ctrl+K** opens a command palette
  that reaches every view and panel your account may open. **?** lists the shortcuts. A shortcut never takes a key you are typing into a field.
- **Screen readers.** Dialogs are native `<dialog>` elements that keep and return focus. Busy buttons say so with `aria-busy`, results and
  errors are announced through a polite live region, expanding lists say whether they are open, and a skip link jumps to the content.
- **Colour.** Text and controls meet WCAG AA contrast (4.5:1) in both the light and dark themes, which a test checks for every colour pair.
  Status never relies on colour alone: health marks have shapes, status words carry a sign (✓, !, ✕), and the map's ports carry a word.
- **Preferences.** Light or dark theme, a compact density, and reduced motion, kept per account in the browser.
- **Small screens.** At 1000 pixels wide and below, the header folds its extra controls behind a **More** button.

## Known limitations

- It has been checked with automated browser tests and by hand from the keyboard, **not with real screen readers** (NVDA, JAWS, VoiceOver,
  Orca) or by people who use them. Expect rough edges there.
- The topology and map are drawn diagrams. Their content is reachable as buttons and lists, but the picture itself has no full text
  equivalent.
- The storage planner's own status dots and theme button do not yet follow the shared shape cues and Preferences.
- It is built for desktop and tablet browsers; phones are not supported.

## Reporting a barrier

Open an issue and say what you were trying to do, what got in the way, and the browser and assistive technology you use. Accessibility
problems are treated as bugs.
