use std::{
    io::{self, Stdout},
    path::Path,
};

use anyhow::{Context, Result};
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{FutureExt, StreamExt};
use oci_spec::image::ImageConfiguration;
use ratatui::{prelude::*, widgets::*};

use tokio::sync::mpsc::Receiver;
use tui_tree_widget_table::{TreeItem, TreeState};

use crate::analyze::LayerAnalysisResult;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
struct RowIdentifier(usize);

#[derive(Copy, Clone, Debug, Default)]
struct RowIdentifierAllocator(usize);

impl RowIdentifierAllocator {
    fn next(&mut self) -> RowIdentifier {
        let id = RowIdentifier(self.0);
        self.0 += 1;
        id
    }
}

fn bytes_to_human_size(byte_size: u64) -> (f64, &'static str) {
    if byte_size > 1024 * 1024 * 1024 {
        (byte_size as f64 / (1024.0 * 1024.0 * 1024.0), "GiB")
    } else if byte_size > 1024 * 1024 {
        (byte_size as f64 / (1024.0 * 1024.0), "MiB")
    } else if byte_size > 1024 {
        (byte_size as f64 / (1024.0), "KiB")
    } else {
        (byte_size as f64, "B")
    }
}

fn mode_to_string(mode: u32) -> String {
    let bits = [
        if mode & 0o400 != 0 { 'r' } else { '-' },
        if mode & 0o200 != 0 { 'w' } else { '-' },
        if mode & 0o100 != 0 { 'x' } else { '-' },
        if mode & 0o040 != 0 { 'r' } else { '-' },
        if mode & 0o020 != 0 { 'w' } else { '-' },
        if mode & 0o010 != 0 { 'x' } else { '-' },
        if mode & 0o004 != 0 { 'r' } else { '-' },
        if mode & 0o002 != 0 { 'w' } else { '-' },
        if mode & 0o001 != 0 { 'x' } else { '-' },
    ];
    bits.into_iter().collect()
}

impl super::DirectoryMetadata {
    fn to_tui_tree_item(
        &self,
        id_allocator: &mut RowIdentifierAllocator,
    ) -> Vec<tui_tree_widget_table::TreeItem<'static, RowIdentifier>> {
        let mut children: Vec<_> = self.children.iter().collect();
        children.sort_unstable_by_key(|(_k, v)| std::cmp::Reverse(v.size()));

        children
            .into_iter()
            .map(|(k, v)| {
                let k = format!("{}", Path::new(k).display());
                let mode = mode_to_string(v.mode);
                let (magnitude, unit) = bytes_to_human_size(v.size);
                let magnitude = (magnitude * 100.0).round() / 100.0;
                let row = Row::new([mode, format!("{magnitude: >7} {unit: <3}")]);

                let style = match v.state {
                    super::LayerFsNodeState::Created => Style::default(),
                    super::LayerFsNodeState::Modified => Style::default().yellow(),
                    super::LayerFsNodeState::ModeChanged => Style::default().blue(),
                    super::LayerFsNodeState::Deleted => Style::default().red(),
                };
                let id = id_allocator.next();
                let node = match &v.node_type {
                    super::LayerFsNodeType::File => {
                        let text = Text::raw(k).style(style);
                        TreeItem::new_leaf_with_data(id, text, row)
                    }
                    super::LayerFsNodeType::Symlink { target } => {
                        let text =
                            Text::raw(format!("{k} -> {}", target.display())).style(style.italic());
                        TreeItem::new_leaf_with_data(id, text, row)
                    }
                    super::LayerFsNodeType::Directory(metadata) => {
                        let text = Text::raw(k).style(style);
                        TreeItem::new_with_data(
                            id,
                            text,
                            metadata.to_tui_tree_item(id_allocator),
                            row,
                        )
                        .unwrap()
                    }
                };

                node
            })
            .collect()
    }
}

pub struct StatefulTree<'a> {
    state: TreeState<RowIdentifier>,
    items: Vec<TreeItem<'a, RowIdentifier>>,
}

impl<'a> StatefulTree<'a> {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            state: TreeState::default(),
            items: Vec::new(),
        }
    }

    fn with_items(items: Vec<TreeItem<'a, RowIdentifier>>) -> Self {
        Self {
            state: TreeState::default(),
            items,
        }
    }

    pub fn first(&mut self) {
        self.state.select_first();
    }

    pub fn last(&mut self) {
        self.state.select_last();
    }

    pub fn down(&mut self) {
        self.state.key_down();
    }

    pub fn up(&mut self) {
        self.state.key_up();
    }

    pub fn left(&mut self) {
        self.state.key_left();
    }

    pub fn right(&mut self) {
        self.state.key_right();
    }

    pub fn toggle(&mut self) {
        self.state.toggle_selected();
    }
}

pub(crate) async fn run_tui(
    image_config: &ImageConfiguration,
    layers: Vec<LayerAnalysisResult>,
) -> Result<()> {
    let (tx, rx) = tokio::sync::mpsc::channel(layers.len());
    for (i, layer) in layers.into_iter().enumerate() {
        tx.send((i, layer)).await.unwrap();
    }
    run_tui_with_channel(image_config, rx).await
}

pub(crate) async fn run_tui_with_channel(
    image_config: &ImageConfiguration,
    layers_receiver: Receiver<(usize, LayerAnalysisResult)>,
) -> Result<()> {
    let mut terminal = setup_terminal().context("setup failed")?;
    run(&mut terminal, image_config, layers_receiver)
        .await
        .context("app loop failed")?;
    restore_terminal(&mut terminal).context("restore terminal failed")?;
    Ok(())
}

/// Setup the terminal. This is where you would enable raw mode, enter the alternate screen, and
/// hide the cursor. This example does not handle errors. A more robust application would probably
/// want to handle errors and ensure that the terminal is restored to a sane state before exiting.
fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    let mut stdout = io::stdout();
    enable_raw_mode().context("failed to enable raw mode")?;
    execute!(stdout, EnterAlternateScreen).context("unable to enter alternate screen")?;
    Terminal::new(CrosstermBackend::new(stdout)).context("creating terminal failed")
}

/// Restore the terminal. This is where you disable raw mode, leave the alternate screen, and show
/// the cursor.
fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("unable to switch to main screen")?;
    terminal.show_cursor().context("unable to show cursor")
}

lazy_static::lazy_static! {
    static ref INACTIVE_BORDER: Block<'static> = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::new().add_modifier(Modifier::DIM).fg(Color::Gray));

    static ref ACTIVE_BORDER: Block<'static> = Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::new().add_modifier(Modifier::BOLD));
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum InputFocus {
    Layers,
    LayerContent,
}

impl InputFocus {
    fn next(self) -> Self {
        match self {
            InputFocus::Layers => InputFocus::LayerContent,
            InputFocus::LayerContent => InputFocus::Layers,
        }
    }

    fn get_border(self, for_pane: InputFocus) -> Block<'static> {
        if self == for_pane {
            ACTIVE_BORDER.clone()
        } else {
            INACTIVE_BORDER.clone()
        }
    }
}

struct TuiState {
    keep_running: bool,

    input_focus: InputFocus,

    // Layers
    layers_table_state: TableState,
    layers_table_row_count: usize,

    // Can't remember what this means exactly, will need a bit of RE later.
    last_height: usize,
}

fn handle_key_event(
    key: KeyEvent,
    tui_state: &mut TuiState,
    chosen_content_tree: Option<&mut StatefulTree>,
) {
    match key.code {
        KeyCode::Char('q') => {
            tui_state.keep_running = false;
            return;
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            tui_state.keep_running = false;
            return;
        }
        KeyCode::Tab => tui_state.input_focus = tui_state.input_focus.next(),
        _ => {}
    }
    if let InputFocus::Layers = tui_state.input_focus {
        let focused_layer = tui_state.layers_table_state.selected().unwrap();

        let new_selection = match key.code {
            KeyCode::Down => focused_layer + 1,
            KeyCode::Up => focused_layer.saturating_sub(1),
            KeyCode::Home => 0,
            KeyCode::End => usize::MAX,
            _ => focused_layer,
        };
        let new_selection = new_selection.clamp(0, tui_state.layers_table_row_count - 1);
        tui_state.layers_table_state.select(Some(new_selection));
    }
    if let InputFocus::LayerContent = tui_state.input_focus {
        if let Some(chosen_content_tree) = chosen_content_tree {
            match key.code {
                KeyCode::Char('\n' | ' ') => chosen_content_tree.toggle(),
                KeyCode::Left => chosen_content_tree.left(),
                KeyCode::Right => chosen_content_tree.right(),
                KeyCode::Down => chosen_content_tree.down(),
                KeyCode::Up => chosen_content_tree.up(),
                KeyCode::Home => chosen_content_tree.first(),
                KeyCode::End => chosen_content_tree.last(),
                KeyCode::PageDown => {
                    for _ in 0..(tui_state.last_height) {
                        chosen_content_tree.down();
                    }
                }
                KeyCode::PageUp => {
                    for _ in 0..(tui_state.last_height) {
                        chosen_content_tree.up();
                    }
                }
                _ => {}
            }
        }
    }
}

fn generate_layer_row(
    config: &oci_spec::image::History,
    layer_size_bytes: Option<u64>,
) -> Row<'static> {
    let layer_size = layer_size_bytes
        .map(|s| {
            let (magnitude, unit) = bytes_to_human_size(s);
            format!("{magnitude:.2} {unit}")
        })
        .unwrap_or(String::from("<Loading>"));

    let created_by = config.created_by().as_ref().unwrap();
    let created_by = created_by
        .strip_prefix("/bin/sh -c #(nop)")
        .unwrap_or(created_by)
        .trim()
        .to_string();
    Row::new([
        Cell::from(format!("{layer_size: >10}")),
        Cell::from(created_by),
    ])
}

/// Run the application loop. This is where you would handle events and update the application
/// state. This example exits when the user presses 'q'. Other styles of application loops are
/// possible, for example, you could have multiple application states and switch between them based
/// on events, or you could have a single application state and update it based on events.
async fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    image_config: &ImageConfiguration,
    mut layers_receiver: tokio::sync::mpsc::Receiver<(usize, LayerAnalysisResult)>,
) -> Result<()> {
    let layer_configs: Vec<_> = image_config
        .history()
        .iter()
        .filter(|f| !f.empty_layer().unwrap_or(false))
        .collect();

    let mut layers: Vec<Option<LayerAnalysisResult>> = layer_configs.iter().map(|_| None).collect();
    let mut layers_ui_state: Vec<Option<StatefulTree>> =
        layer_configs.iter().map(|_| None).collect();

    let mut layer_table_items = layer_configs
        .iter()
        .map(|config| generate_layer_row(config, None))
        .collect::<Vec<_>>();

    let highlight_style = Style::new()
        .fg(Color::Black)
        .bg(Color::LightGreen)
        .add_modifier(Modifier::BOLD);

    let mut event_stream = EventStream::new();
    let mut tui_state = TuiState {
        keep_running: true,
        input_focus: InputFocus::Layers,

        layers_table_state: TableState::default().with_selected(Some(0)),
        layers_table_row_count: layer_table_items.len(),
        last_height: 0,
    };

    while tui_state.keep_running {
        let focused_layer = tui_state.layers_table_state.selected().unwrap();
        let chosen_content_tree = &mut layers_ui_state[focused_layer];

        terminal.draw(|frame| {
            let whole_screen = frame.area();
            let right_half = Rect::new(
                whole_screen.width / 2,
                0,
                whole_screen.width / 2,
                whole_screen.height,
            );
            let left_half = Rect { x: 0, ..right_half };
            let layers_pane_area = Rect {
                height: left_half.height / 4,
                ..left_half
            };
            let layer_details_pane_area = Rect {
                y: layers_pane_area.height,
                ..layers_pane_area
            };
            tui_state.last_height = right_half.height as usize - 2;

            frame.render_stateful_widget(
                ratatui::widgets::Table::new(
                    layer_table_items.clone(),
                    &[Constraint::Length(10), Constraint::Percentage(100)],
                )
                .block(
                    tui_state
                        .input_focus
                        .get_border(InputFocus::Layers)
                        .title("Layers"),
                )
                .column_spacing(2)
                .row_highlight_style(highlight_style)
                .header(Row::new([format!("{: >10}", "Size"), "Command".into()]).bold()),
                layers_pane_area,
                &mut tui_state.layers_table_state,
            );

            let layer_config = image_config
                .history()
                .iter()
                .filter(|f| !f.empty_layer().unwrap_or(false))
                .nth(focused_layer)
                .unwrap();

            let mut details = vec![format!(
                "Digest: {}",
                layers[focused_layer]
                    .as_ref()
                    .map(|layer| &*layer.digest)
                    .unwrap_or("Loading")
            )];

            if let Some(created_by) = layer_config.created_by() {
                details.push(format!("Created by: {}", created_by));
            }
            if let Some(comment) = layer_config.comment() {
                details.push(format!("Comment: {}", comment));
            }

            frame.render_widget(
                ratatui::widgets::Paragraph::new(details.join("\n"))
                    .wrap(Wrap::default())
                    .block(INACTIVE_BORDER.clone().title("Layer Details")),
                layer_details_pane_area,
            );

            if let Some(chosen_content_tree) = chosen_content_tree {
                let items = tui_tree_widget_table::Tree::new(&chosen_content_tree.items)
                    .unwrap()
                    .block(
                        tui_state
                            .input_focus
                            .get_border(InputFocus::LayerContent)
                            .title("Layer Content"),
                    )
                    .highlight_style(highlight_style)
                    .table_header(Some(Row::new(["   Mode", "     Size"]).bold().underlined()))
                    .table_widths(&[Constraint::Length(10), Constraint::Length(11)]);
                frame.render_stateful_widget(items, right_half, &mut chosen_content_tree.state);
            }
        })?;

        let f = event_stream.next().fuse();

        tokio::select! {
            Some(event) = f => {
                if let Event::Key(key) = event.unwrap() {
                    handle_key_event(key, &mut tui_state, chosen_content_tree.into());
                }
            }

            Some((index, layer)) = layers_receiver.recv() => {
                let mut id_allocator = RowIdentifierAllocator::default();
                layers_ui_state[index] = Some(StatefulTree::with_items(
                    layer
                        .file_system
                        .unwrap_dir()
                        .to_tui_tree_item(&mut id_allocator)));
                layer_table_items[index] = generate_layer_row(layer_configs[index], Some(layer.file_system.size()));
                layers[index] = Some(layer);
            }
        };
    }

    Ok(())
}
