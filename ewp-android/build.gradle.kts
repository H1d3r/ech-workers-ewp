// 仓库配置已移至 settings.gradle.kts（RepositoriesMode.FAIL_ON_PROJECT_REPOS）
plugins {
    id("com.android.application") version "8.2.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.20" apply false
}

tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}
