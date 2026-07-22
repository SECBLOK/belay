import { useState, type FormEvent } from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import ModelPicker from "./ModelPicker";

// Test-local controlled wrapper mirroring how the settings form (Task 2) will
// actually drive this component: `value` lives in parent state and round-trips
// through `onChange`, exactly like a real controlled input.
function ControlledModelPicker() {
  const [value, setValue] = useState<string | null>(null);
  return (
    <ModelPicker
      value={value}
      inherited="qwen2.5"
      label="Explanation model"
      onChange={setValue}
    />
  );
}

describe("ModelPicker", () => {
  it("shows Inherit active and no Recommended segment when recommended is absent", () => {
    render(
      <ModelPicker value={null} inherited="qwen2.5" label="Explanation model" onChange={vi.fn()} />,
    );
    expect(screen.getByRole("radio", { name: /inherit/i })).toHaveAttribute("aria-checked", "true");
    expect(screen.queryByRole("radio", { name: /recommended/i })).toBeNull();
  });

  it("renders the Recommended segment and selects the recommended id when clicked", () => {
    const onChange = vi.fn();
    render(
      <ModelPicker
        value={null}
        inherited="claude-haiku-4-5"
        recommended="claude-sonnet-5"
        note="Sonnet for the more demanding judge task."
        label="Judge model"
        onChange={onChange}
      />,
    );
    fireEvent.click(screen.getByRole("radio", { name: /recommended/i }));
    expect(onChange).toHaveBeenCalledWith("claude-sonnet-5");
    expect(screen.getByText(/more demanding judge task/i)).toBeTruthy();
  });

  it("Inherit emits null", () => {
    const onChange = vi.fn();
    render(
      <ModelPicker value="claude-sonnet-5" inherited="claude-haiku-4-5" recommended="claude-sonnet-5" label="Judge model" onChange={onChange} />,
    );
    fireEvent.click(screen.getByRole("radio", { name: /inherit/i }));
    expect(onChange).toHaveBeenCalledWith(null);
  });

  it("Custom reveals a free-text field that emits its value", () => {
    const onChange = vi.fn();
    render(
      <ModelPicker value={null} inherited="qwen2.5" label="Explanation model" onChange={onChange} />,
    );
    fireEvent.click(screen.getByRole("radio", { name: /custom/i }));
    const input = screen.getByLabelText(/explanation model custom id/i);
    fireEvent.change(input, { target: { value: "gpt-5.5" } });
    expect(onChange).toHaveBeenCalledWith("gpt-5.5");
  });

  it("starts on Custom with the field pre-filled when value is a non-recommended id", () => {
    render(
      <ModelPicker value="my-weird-model" inherited="qwen2.5" recommended="claude-sonnet-5" label="Judge model" onChange={vi.fn()} />,
    );
    expect(screen.getByRole("radio", { name: /custom/i })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByLabelText(/judge model custom id/i)).toHaveValue("my-weird-model");
  });

  it("does not collapse back to Inherit when a controlled parent round-trips an empty Custom value", () => {
    render(<ControlledModelPicker />);
    fireEvent.click(screen.getByRole("radio", { name: /custom/i }));
    // Under the old code, onChange("") -> parent sets value="" -> the sync effect
    // re-derives segmentFor("") === "inherit" and the input vanishes here.
    const input = screen.getByLabelText(/explanation model custom id/i);
    expect(input).toBeInTheDocument();
    fireEvent.change(input, { target: { value: "gpt-5.5" } });
    expect(screen.getByLabelText(/explanation model custom id/i)).toHaveValue("gpt-5.5");
  });

  it("segment buttons are type=button so they don't submit an enclosing form", () => {
    const onSubmit = vi.fn((e: FormEvent) => e.preventDefault());
    render(
      <form onSubmit={onSubmit}>
        <ModelPicker value={null} inherited="qwen2.5" label="Explanation model" onChange={vi.fn()} />
      </form>,
    );
    fireEvent.click(screen.getByRole("radio", { name: /custom/i }));
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
