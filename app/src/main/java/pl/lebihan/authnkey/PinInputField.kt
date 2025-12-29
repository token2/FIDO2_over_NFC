package pl.lebihan.authnkey

import android.content.Context
import android.text.InputType
import android.util.AttributeSet
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import androidx.core.content.withStyledAttributes
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.google.android.material.theme.overlay.MaterialThemeOverlay
import androidx.core.view.isVisible

/**
 * A reusable PIN input field that extends [TextInputLayout] with:
 * - Password visibility toggle
 * - Switchable numeric/alphanumeric keyboard
 * - Built-in validation for minimum PIN length
 *
 * Configure via XML attributes [R.styleable.PinInputField] or programmatically.
 */
class PinInputField @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = com.google.android.material.R.attr.textInputStyle
) : TextInputLayout(
    MaterialThemeOverlay.wrap(context, attrs, defStyleAttr, 0),
    attrs,
    defStyleAttr
) {

    private val pinEditText = TextInputEditText(this.context).apply {
        layoutParams = LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT)
        imeOptions = EditorInfo.IME_ACTION_DONE
    }

    /**
     * Whether to use a numeric keyboard. Updating this property will immediately
     * update the keyboard type and toggle icon.
     */
    var useNumericKeyboard: Boolean = true
        set(value) {
            if (field != value) {
                field = value
                applyKeyboardMode()
            }
        }

    /**
     * Callback invoked when the user toggles the keyboard mode via the start icon.
     * Use this to persist the preference if desired.
     */
    var onKeyboardModeChanged: ((Boolean) -> Unit)? = null

    /**
     * Minimum PIN length for validation. Defaults to 4.
     */
    var minPinLength: Int = 4

    init {
        addView(pinEditText)

        context.withStyledAttributes(attrs, R.styleable.PinInputField) {
            hint = getString(R.styleable.PinInputField_pinHint)
                ?: context.getString(R.string.pin_hint)
            minPinLength = getInt(R.styleable.PinInputField_minPinLength, 4)
        }

        endIconMode = END_ICON_PASSWORD_TOGGLE
        setStartIconContentDescription(R.string.toggle_keyboard_type)
        setStartIconOnClickListener { onKeyboardModeToggled() }

        applyKeyboardMode(false)
    }

    /**
     * The current PIN text.
     */
    val pin: String?
        get() = pinEditText.text?.toString()

    /**
     * Validates the PIN against [minPinLength].
     * Sets the error message if invalid, clears it if valid.
     * @return true if valid, false otherwise
     */
    fun validate(): Boolean {
        val currentPin = pin
        return if (currentPin != null && currentPin.length >= minPinLength) {
            error = null
            true
        } else {
            error = context.getString(R.string.pin_too_short, minPinLength)
            false
        }
    }

    /**
     * Validates the PIN against [minPinLength]. Returns the PIN if valid,
     * or null if invalid (also sets the error message).
     */
    fun validateAndGetPin(): String? {
        return if (validate()) pin else null
    }

    /**
     * Clears the PIN text and any error message.
     */
    fun clear() {
        pinEditText.text?.clear()
        error = null
    }

    /**
     * Requests focus and shows the soft keyboard.
     */
    fun focus() {
        pinEditText.requestFocus()
        pinEditText.post {
            val imm = context.getSystemService(InputMethodManager::class.java)
            imm?.showSoftInput(pinEditText, InputMethodManager.SHOW_IMPLICIT)
        }
    }

    /**
     * Sets a callback for the IME "Done" action.
     */
    fun setOnDoneAction(action: () -> Unit) {
        pinEditText.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                action()
                true
            } else {
                false
            }
        }
    }

    override fun setVisibility(visibility: Int) {
        if (visibility != VISIBLE && pinEditText.hasFocus()) {
            val imm = context.getSystemService(InputMethodManager::class.java)
            imm?.hideSoftInputFromWindow(pinEditText.windowToken, 0)
        }
        super.setVisibility(visibility)
    }

    private fun applyKeyboardMode(animate: Boolean = true) {
        val iconRes = if (useNumericKeyboard) R.drawable.keyboard_24 else R.drawable.dialpad_24

        if (animate && isVisible) {
            findViewById<View>(com.google.android.material.R.id.text_input_start_icon)?.let { iconView ->
                iconView.animate()
                    .alpha(0f)
                    .setDuration(ICON_ANIMATION_DURATION)
                    .withEndAction {
                        setStartIconDrawable(iconRes)
                        iconView.alpha = 1f
                    }
                    .start()
            } ?: setStartIconDrawable(iconRes)
        } else {
            setStartIconDrawable(iconRes)
        }

        pinEditText.inputType = if (useNumericKeyboard) {
            InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        } else {
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
    }

    private fun onKeyboardModeToggled() {
        useNumericKeyboard = !useNumericKeyboard
        onKeyboardModeChanged?.invoke(useNumericKeyboard)

        pinEditText.post {
            val imm = context.getSystemService(InputMethodManager::class.java)
            imm?.restartInput(pinEditText)
        }
    }

    private companion object {
        const val ICON_ANIMATION_DURATION = 100L
    }
}
