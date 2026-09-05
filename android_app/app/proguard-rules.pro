# Project configuration for artoolkit Android App
# Keep the original class names and methods
-keep public class com.tmx.armcp.** {
    public protected *;
}

# Keep the layout resources
-keepclassmembers class * {
    @android.view.OnClick <methods>;
}