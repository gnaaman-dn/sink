use std::io::{self, Stdout};

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use oci_spec::image::ImageConfiguration;
use ratatui::{prelude::*, widgets::*};

use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use tui_tree_widget::{TreeItem, TreeState};

use crate::analyze::LayerAnalysisResult;
pub struct StatefulTree<'a> {
    pub state: TreeState,
    pub items: Vec<TreeItem<'a>>,
}

impl<'a> StatefulTree<'a> {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            state: TreeState::default(),
            items: Vec::new(),
        }
    }

    pub fn with_items(items: Vec<TreeItem<'a>>) -> Self {
        Self {
            state: TreeState::default(),
            items,
        }
    }

    pub fn first(&mut self) {
        self.state.select_first();
    }

    pub fn last(&mut self) {
        self.state.select_last(&self.items);
    }

    pub fn down(&mut self) {
        self.state.key_down(&self.items);
    }

    pub fn up(&mut self) {
        self.state.key_up(&self.items);
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

/// This is a bare minimum example. There are many approaches to running an application loop, so
/// this is not meant to be prescriptive. It is only meant to demonstrate the basic setup and
/// teardown of a terminal application.
///
/// A more robust application would probably want to handle errors and ensure that the terminal is
/// restored to a sane state before exiting. This example does not do that. It also does not handle
/// events or update the application state. It just draws a greeting and exits when the user
/// presses 'q'.
pub(crate) fn run_tui(
    image_config: &ImageConfiguration,
    layers: &[LayerAnalysisResult],
) -> Result<()> {
    let mut terminal = setup_terminal().context("setup failed")?;
    run(&mut terminal, image_config, layers).context("app loop failed")?;
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

const INACTIVE_BORDER: Block = Block::new()
    .borders(Borders::ALL)
    .border_style(Style::new().add_modifier(Modifier::DIM).fg(Color::Gray));
const ACTIVE_BORDER: Block = Block::new()
    .borders(Borders::ALL)
    .border_type(BorderType::Thick)
    .border_style(Style::new().add_modifier(Modifier::BOLD));

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
            ACTIVE_BORDER
        } else {
            INACTIVE_BORDER
        }
    }
}

/// Run the application loop. This is where you would handle events and update the application
/// state. This example exits when the user presses 'q'. Other styles of application loops are
/// possible, for example, you could have multiple application states and switch between them based
/// on events, or you could have a single application state and update it based on events.
fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    image_config: &ImageConfiguration,
    layers: &[LayerAnalysisResult],
) -> Result<()> {
    let mut layer_data: Vec<_> = layers
        .par_iter()
        .map(|layer| StatefulTree::with_items(layer.file_system.unwrap_dir().into_tui_tree_item()))
        .collect();

    let layer_configs: Vec<_> = image_config
        .history()
        .iter()
        .filter(|f| !f.empty_layer().unwrap_or(false))
        .collect();

    let layer_table_items = layers
        .iter()
        .zip(layer_configs.iter())
        .map(|(layer, config)| {
            let (magnitude, unit) = super::bytes_to_human_size(layer.file_system.size());
            let size_line = format!("{magnitude:.0} {unit}");
            Row::new([
                Cell::from(format!("{size_line: >10}")),
                Cell::from(config.created_by().as_ref().unwrap().clone()),
            ])
        })
        .collect::<Vec<_>>();

    // let layer_list_items = layer_configs
    //     .iter()
    //     .map(|l| ListItem::new(l.created_by().as_deref().unwrap_or("<N/A>")))
    //     .collect::<Vec<_>>();
    // let mut layer_list_state = ListState::default().with_selected(Some(0));
    let mut layers_table_state = TableState::default().with_selected(Some(0));
    let mut input_focus = InputFocus::Layers;

    let highlight_style = Style::new()
        .fg(Color::Black)
        .bg(Color::LightGreen)
        .add_modifier(Modifier::BOLD);

    let mut last_height = 0;

    loop {
        let focused_layer = layers_table_state.selected().unwrap();
        let chosen_content_tree = &mut layer_data[focused_layer];

        terminal.draw(|frame| {
            let whole_screen = frame.size();
            let right_half = Rect::new(
                whole_screen.width / 2,
                0,
                whole_screen.width / 2,
                whole_screen.height,
            );
            let left_half = Rect { x: 0, ..right_half };
            let layers_pane_area = Rect {
                height: 10,
                ..left_half
            };
            let layer_details_pane_area = Rect {
                y: layers_pane_area.y + 10,
                ..layers_pane_area
            };
            last_height = right_half.height - 2;

            frame.render_stateful_widget(
                ratatui::widgets::Table::new(layer_table_items.clone())
                    .block(input_focus.get_border(InputFocus::Layers).title("Layers"))
                    .widths(&[Constraint::Length(10), Constraint::Percentage(100)])
                    .column_spacing(2)
                    .highlight_style(highlight_style)
                    .header(Row::new([format!("{: >10}", "Size"), "Command".into()]).bold()),
                layers_pane_area,
                &mut layers_table_state,
            );

            let layer_config = image_config
                .history()
                .iter()
                .filter(|f| !f.empty_layer().unwrap_or(false))
                .nth(focused_layer)
                .unwrap();

            let mut details = vec![format!("Digest: {}", layers[focused_layer].digest)];

            if let Some(created_by) = layer_config.created_by() {
                details.push(format!("Created by: {}", created_by));
            }
            if let Some(comment) = layer_config.comment() {
                details.push(format!("Comment: {}", comment));
            }

            frame.render_widget(
                ratatui::widgets::Paragraph::new(details.join("\n"))
                    .wrap(Wrap::default())
                    .block(INACTIVE_BORDER.title("Layer Details")),
                layer_details_pane_area,
            );

            let items = tui_tree_widget::Tree::new(chosen_content_tree.items.clone())
                .block(
                    input_focus
                        .get_border(InputFocus::LayerContent)
                        .title("Layer Content"),
                )
                .highlight_style(highlight_style);
            frame.render_stateful_widget(items, right_half, &mut chosen_content_tree.state);
        })?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(())
                }
                KeyCode::Tab => input_focus = input_focus.next(),
                _ => {}
            }
            if let InputFocus::Layers = input_focus {
                let new_selection = match key.code {
                    KeyCode::Down => focused_layer + 1,
                    KeyCode::Up => focused_layer.saturating_sub(1),
                    KeyCode::Home => 0,
                    KeyCode::End => usize::MAX,
                    _ => focused_layer,
                };
                let new_selection = new_selection.clamp(0, layer_table_items.len() - 1);
                layers_table_state.select(Some(new_selection));
            }
            if let InputFocus::LayerContent = input_focus {
                match key.code {
                    KeyCode::Char('\n' | ' ') => chosen_content_tree.toggle(),
                    KeyCode::Left => chosen_content_tree.left(),
                    KeyCode::Right => chosen_content_tree.right(),
                    KeyCode::Down => chosen_content_tree.down(),
                    KeyCode::Up => chosen_content_tree.up(),
                    KeyCode::Home => chosen_content_tree.first(),
                    KeyCode::End => chosen_content_tree.last(),
                    KeyCode::PageDown => {
                        for _ in 0..(last_height) {
                            chosen_content_tree.down();
                        }
                    }
                    KeyCode::PageUp => {
                        for _ in 0..(last_height) {
                            chosen_content_tree.up();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
